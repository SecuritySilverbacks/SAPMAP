#!/usr/bin/env python3
"""Tests for the dpmon virtual SAP* primitive.

Coverage:
  * `_kernel_ge` numeric kernel parser (handles "790", "7.90", "7_90",
    edge cases).
  * `is_dpmon_sap_star_available` gate (kernel >= 790 AND ABAP stack).
  * `_build_activation_input` / `_build_list_input` / `_build_delete_input`
    produce the menu sequence that matches the live kernel-790+ walkthrough.
  * `_build_dpmon_command` wraps the menu input in the auto-discovery
    shell pipeline.
  * `parse_dpmon_activation_output` correctly extracts the OTP and
    confirmed client/validity from real captured dpmon output.
  * `activate_virtual_sap_star` glues input validation, exec_fn calls,
    and parsing into a clean public API.

No live SAP system needed — every test uses synthetic fixtures or a
mocked exec_fn.
"""
from __future__ import annotations

import base64
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "exploitation"))


# ===========================================================================
# Test fixture: VERBATIM output captured from a live kernel-790+ system.
# Operator ran `dpmon` interactively, walked m -> u -> c -> 000 -> 10 -> y,
# screenshotted the result.  This block is the screen text exactly as
# dpmon printed it — including the trailing "Press any key to return."
# ===========================================================================

LIVE_DPMON_OUTPUT_SUCCESS = """\
   Virtual SAP* user
   --------------------
   c - create
   d - delete
   l - list
   q - quit
   m - menu

--> c

   Enter client id (3 digits):
   m - menu

Client --> 000

   Enter validity (in minutes) [default=10 min]:
   m - menu

Validity --> 10

   Continue with [client = 000] [validity = 10 min]?

   [ Y - yes | n - no | m - menu | q - quit ]

--> y
   Access unlocked. [client = 000] [validity = 10 min].
   Password:
   ----------------------------------------
   IAQMC2TPJWN2SBXTYVAIXTCXX7W7USHTTTYARNSW
   ----------------------------------------
   Press any key to return.
"""


# ===========================================================================
# _kernel_ge
# ===========================================================================

@pytest.mark.parametrize("kernel,target,expected", [
    # Happy path — standard 3-digit kernel strings
    ("790",  790, True),
    ("791",  790, True),
    ("793",  790, True),
    ("789",  790, False),
    ("753",  790, False),
    ("749",  790, False),
    # Dotted format
    ("7.90", 790, True),
    ("7.93", 790, True),
    ("7.53", 790, False),
    # Underscore format (rare but seen on some installer outputs)
    ("7_90", 790, True),
    ("7_53", 790, False),
    # Edge: 4-digit future kernel
    ("1000", 790, True),
    # Edge: empty / None / garbage
    ("",     790, False),
    ("abc",  790, False),
    ("???",  790, False),
])
def test_kernel_ge(kernel, target, expected):
    from sap_dpmon_sapstar import _kernel_ge
    assert _kernel_ge(kernel, target) is expected, (
        f"_kernel_ge({kernel!r}, {target}) -> expected {expected}")


def test_kernel_ge_handles_none():
    from sap_dpmon_sapstar import _kernel_ge
    assert _kernel_ge(None, 790) is False  # type: ignore[arg-type]


# ===========================================================================
# is_dpmon_sap_star_available — kernel AND ABAP gate
# ===========================================================================

@pytest.mark.parametrize("kernel,system_type,expected", [
    # ABAP + kernel >= 790 → eligible
    ("790", "ABAP",      True),
    ("793", "ABAP",      True),
    ("790", "ABAP+JAVA", True),  # dual-stack still has ABAP runtime
    # ABAP + kernel < 790 → not eligible
    ("753", "ABAP",      False),
    ("749", "ABAP+JAVA", False),
    # No ABAP stack → never eligible regardless of kernel
    ("790", "JAVA",            False),
    ("790", "HANA",            False),
    ("790", "WEB_DISPATCHER",  False),
    ("790", "SAPROUTER",       False),
    ("790", "",                False),
    # Missing kernel info → not eligible
    ("",    "ABAP", False),
    # Lowercase ABAP — system_type comparison is case-insensitive
    ("790", "abap", True),
])
def test_is_dpmon_sap_star_available(kernel, system_type, expected):
    from sap_dpmon_sapstar import is_dpmon_sap_star_available
    assert is_dpmon_sap_star_available(kernel, system_type) is expected


# ===========================================================================
# Menu input builders
# ===========================================================================

def test_build_activation_input_matches_live_walkthrough():
    """The piped input MUST match the key sequence that drove the live
    kernel-790+ walkthrough end-to-end: m, u, c, <client>, <duration>,
    y, <Enter>, q, q, q."""
    from sap_dpmon_sapstar import _build_activation_input
    inp = _build_activation_input("001", 10)
    expected = "m\nu\nc\n001\n10\ny\n\nq\nq\nq\n"
    assert inp == expected, (
        f"activation input must match the live menu sequence; got: "
        f"{inp!r}")


def test_build_activation_input_passes_client_and_duration_verbatim():
    from sap_dpmon_sapstar import _build_activation_input
    inp = _build_activation_input("100", 30)
    assert "\n100\n" in inp
    assert "\n30\n" in inp


def test_build_list_input_walks_to_l_submenu():
    from sap_dpmon_sapstar import _build_list_input
    inp = _build_list_input()
    # First three menu hops must be m -> u -> l (Queue -> Monitor ->
    # Virtual SAP* -> list)
    assert inp.startswith("m\nu\nl\n")
    # Must quit cleanly (3 q's: SAP*-submenu, Monitor-Menue, dpmon)
    assert inp.count("q\n") >= 3


def test_build_delete_input_walks_to_d_with_client():
    from sap_dpmon_sapstar import _build_delete_input
    inp = _build_delete_input("066")
    # Menu hops: m -> u -> d -> <client> -> y (confirm) -> <Enter>
    assert inp.startswith("m\nu\nd\n066\ny\n")
    # Must quit cleanly
    assert inp.count("q\n") >= 3


# ===========================================================================
# _build_dpmon_command — shell wrapper
# ===========================================================================

def test_build_dpmon_command_uses_lang_c_and_combines_streams():
    """LANG=C must be set so dpmon emits English (parser anchors are
    English-only).  Both stdout and stderr must be captured (2>&1) so
    the parser sees the SAPMAP_DPMON_NOT_FOUND sentinel when applicable."""
    from sap_dpmon_sapstar import _build_dpmon_command
    cmd = _build_dpmon_command("S4H", "m\nu\nc\n001\n10\ny\n\nq\nq\nq\n")
    assert "LANG=C" in cmd, "LANG=C must be set for English output"
    assert "2>&1" in cmd, "stderr must be captured for diagnostics"


def test_build_dpmon_command_resolves_via_find_when_no_path():
    """When dpmon_path is not given, the command must auto-discover via
    `find` under /usr/sap/<SID> and /sapmnt/<SID>."""
    from sap_dpmon_sapstar import _build_dpmon_command
    cmd = _build_dpmon_command("S4H", "m\n")
    assert "find /usr/sap/S4H /sapmnt/S4H" in cmd
    assert "-name dpmon" in cmd
    assert "-type f" in cmd
    assert "-executable" in cmd


def test_build_dpmon_command_respects_explicit_path():
    """If the caller provides dpmon_path, the command uses it verbatim
    and skips the find step."""
    from sap_dpmon_sapstar import _build_dpmon_command
    cmd = _build_dpmon_command("S4H", "m\n",
                                dpmon_path="/opt/sap/exe/dpmon")
    assert "/opt/sap/exe/dpmon" in cmd
    assert "find " not in cmd


def test_build_dpmon_command_base64_encodes_input():
    """Menu input goes through base64 + `base64 -d` to bypass every
    shell-quoting / locale headache."""
    from sap_dpmon_sapstar import _build_dpmon_command
    sample = "m\nu\nc\n001\n10\ny\n"
    expected_b64 = base64.b64encode(sample.encode("utf-8")).decode("ascii")
    cmd = _build_dpmon_command("S4H", sample)
    assert expected_b64 in cmd
    assert "base64 -d" in cmd


def test_build_dpmon_command_emits_not_found_sentinel():
    """If the find step turns up nothing, the wrapper must emit the
    SAPMAP_DPMON_NOT_FOUND sentinel to stderr so the parser knows."""
    from sap_dpmon_sapstar import _build_dpmon_command
    cmd = _build_dpmon_command("S4H", "m\n")
    assert "SAPMAP_DPMON_NOT_FOUND" in cmd


def test_build_dpmon_command_uppercases_sid_in_paths():
    """SAP install dirs are uppercase regardless of the SID's case in
    SAPMAP state.  The find paths must use uppercase."""
    from sap_dpmon_sapstar import _build_dpmon_command
    cmd = _build_dpmon_command("s4h", "m\n")
    assert "/usr/sap/S4H" in cmd
    assert "/sapmnt/S4H" in cmd


# ===========================================================================
# parse_dpmon_activation_output — the regex that matters most
# ===========================================================================

def test_parse_live_capture_extracts_otp():
    """The verbatim screen text from the operator's kernel-790+ run
    must yield a clean, successful parse."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    result = parse_dpmon_activation_output(LIVE_DPMON_OUTPUT_SUCCESS)
    assert result["success"] is True, (
        f"live capture should parse as success; got error={result['error']!r}")
    assert result["otp"] == "IAQMC2TPJWN2SBXTYVAIXTCXX7W7USHTTTYARNSW", (
        f"OTP mismatch: got {result['otp']!r}")
    assert result["client"] == "000"
    assert result["validity_min"] == 10
    assert result["error"] == ""


def test_parse_handles_different_client_and_validity():
    """Synthetic variants — different client numbers and validity
    minutes within the [10, 30] range."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    out = (
        "   Access unlocked. [client = 100] [validity = 30 min].\n"
        "   Password:\n"
        "   ----------------------------------------\n"
        "   ABCDEFGHIJ2345MNOPQRSTUVWXYZ2345MNOPQRST\n"
        "   ----------------------------------------\n"
        "   Press any key to return.\n"
    )
    r = parse_dpmon_activation_output(out)
    assert r["success"] is True
    assert r["client"] == "100"
    assert r["validity_min"] == 30
    assert r["otp"] == "ABCDEFGHIJ2345MNOPQRSTUVWXYZ2345MNOPQRST"


def test_parse_empty_output_fails_cleanly():
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    r = parse_dpmon_activation_output("")
    assert r["success"] is False
    assert r["otp"] == ""
    assert "no output" in r["error"].lower()


def test_parse_detects_dpmon_timeout_sentinel():
    """When the worker's `timeout 60 dpmon` guard fires, the parser
    must surface a clear "dpmon hung — env probably not loaded"
    error including the captured env dump."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    out = (
        "[12:00:00] invoking dpmon\n"
        "[12:01:00] dpmon returned exit=124\n"
        "SAPMAP_DPMON_TIMEOUT\n"
        "--- last 30 lines of dpmon output before kill ---\n"
        "Queue Statistics ...\n"
        "--- env dump (vars dpmon may need) ---\n"
        "SAPSYSTEMNAME=S4H\n"
        "HOME=/home/s4hadm\n"
    )
    r = parse_dpmon_activation_output(out)
    assert r["success"] is False
    assert "dpmon hung" in r["error"].lower()
    # Diagnostic must be surfaced for the operator
    assert "SAPSYSTEMNAME" in r["error"] or "env" in r["error"].lower()


def test_parse_detects_dpmon_not_found_sentinel():
    """The wrapper's path-resolver emits SAPMAP_DPMON_NOT_FOUND to
    stderr (captured into combined output) when find finds nothing."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    r = parse_dpmon_activation_output("SAPMAP_DPMON_NOT_FOUND\n")
    assert r["success"] is False
    assert "not found" in r["error"].lower()


def test_parse_success_line_without_otp_returns_error():
    """Edge case: dpmon prints 'Access unlocked.' but the OTP block
    is missing (truncated output, broken pipe, etc.).  Must not
    falsely succeed."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    out = (
        "   Access unlocked. [client = 000] [validity = 10 min].\n"
        "   Password:\n"
        "   (output truncated)\n"
    )
    r = parse_dpmon_activation_output(out)
    assert r["success"] is False
    assert r["otp"] == ""
    assert "could not be extracted" in r["error"].lower()
    # The applied client / validity are still recovered.
    assert r["client"] == "000"
    assert r["validity_min"] == 10


def test_parse_detects_max_20_limit_error():
    """When the per-system 20-concurrent limit is hit, dpmon refuses
    activation.  The parser should classify this distinctly so the
    operator can react (delete one + retry)."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    out = (
        "   Cannot create virtual SAP* user — maximum of 20 active "
        "users exceeded\n"
    )
    r = parse_dpmon_activation_output(out)
    assert r["success"] is False
    assert "limit of 20" in r["error"].lower() or "20" in r["error"]


def test_parse_permission_denied_classified():
    """OS-exec ran as a wrong identity (not <sid>adm / root)."""
    from sap_dpmon_sapstar import parse_dpmon_activation_output
    out = "/sapmnt/S4H/exe/dpmon: Permission denied\n"
    r = parse_dpmon_activation_output(out)
    assert r["success"] is False
    assert "permission denied" in r["error"].lower()


# ===========================================================================
# activate_virtual_sap_star — public API, mocked exec_fn
# ===========================================================================

def _fake_exec_returning(stdout: str):
    """Build an exec_fn that always returns the given stdout and
    records the invocation args."""
    calls = []
    def fake(cmd: str) -> str:
        calls.append(cmd)
        return stdout
    fake.calls = calls
    return fake


def test_activate_happy_path_returns_otp():
    """End-to-end happy path with the verbatim live capture."""
    from sap_dpmon_sapstar import activate_virtual_sap_star
    exec_fn = _fake_exec_returning(LIVE_DPMON_OUTPUT_SUCCESS)
    r = activate_virtual_sap_star(exec_fn, "S4H", "00", "000",
                                   duration_min=10)
    assert r["success"] is True
    assert r["otp"] == "IAQMC2TPJWN2SBXTYVAIXTCXX7W7USHTTTYARNSW"
    assert r["client"] == "000"
    assert r["validity_min"] == 10
    assert r["requested_duration_min"] == 10
    # stdout passes through verbatim
    assert r["stdout"] == LIVE_DPMON_OUTPUT_SUCCESS


def test_activate_normalises_short_client_to_3_digits():
    """`client='1'` should pad to `'001'` in the menu input."""
    from sap_dpmon_sapstar import activate_virtual_sap_star
    exec_fn = _fake_exec_returning("")  # we only care about the cmd
    activate_virtual_sap_star(exec_fn, "S4H", "00", "1")
    cmd = exec_fn.calls[0]
    # Decode the base64 payload and check the client embedded
    import re as _re
    m = _re.search(r"echo (\S+) \| base64 -d", cmd)
    assert m, f"command shape changed: {cmd}"
    decoded = base64.b64decode(m.group(1)).decode("utf-8")
    assert "\n001\n" in decoded


def test_activate_clamps_duration_below_10():
    """Requested duration 5 → clamped to 10 in the menu input."""
    from sap_dpmon_sapstar import activate_virtual_sap_star
    exec_fn = _fake_exec_returning("")
    r = activate_virtual_sap_star(exec_fn, "S4H", "00", "001",
                                   duration_min=5)
    # The requested value is preserved in the response shape
    assert r["requested_duration_min"] == 5
    # But the menu input uses 10
    import re as _re
    m = _re.search(r"echo (\S+) \| base64 -d", exec_fn.calls[0])
    decoded = base64.b64decode(m.group(1)).decode("utf-8")
    assert "\n10\n" in decoded


def test_activate_clamps_duration_above_30():
    """Requested duration 999 → clamped to 30."""
    from sap_dpmon_sapstar import activate_virtual_sap_star
    exec_fn = _fake_exec_returning("")
    r = activate_virtual_sap_star(exec_fn, "S4H", "00", "001",
                                   duration_min=999)
    assert r["requested_duration_min"] == 999
    import re as _re
    m = _re.search(r"echo (\S+) \| base64 -d", exec_fn.calls[0])
    decoded = base64.b64decode(m.group(1)).decode("utf-8")
    assert "\n30\n" in decoded


def test_activate_rejects_non_numeric_client():
    from sap_dpmon_sapstar import activate_virtual_sap_star
    exec_fn = _fake_exec_returning("should not be called")
    r = activate_virtual_sap_star(exec_fn, "S4H", "00", "abc")
    assert r["success"] is False
    assert "invalid client" in r["error"].lower()
    # exec_fn must NOT have been called — input validation runs first
    assert exec_fn.calls == []


def test_activate_handles_exec_fn_raising():
    from sap_dpmon_sapstar import activate_virtual_sap_star
    def boom(cmd):
        raise RuntimeError("RFC connection lost")
    r = activate_virtual_sap_star(boom, "S4H", "00", "001")
    assert r["success"] is False
    assert "RFC connection lost" in r["error"]


def test_activate_uses_explicit_dpmon_path_in_command():
    from sap_dpmon_sapstar import activate_virtual_sap_star
    exec_fn = _fake_exec_returning("")
    activate_virtual_sap_star(exec_fn, "S4H", "00", "001",
                               dpmon_path="/opt/sap/exe/dpmon")
    cmd = exec_fn.calls[0]
    assert "/opt/sap/exe/dpmon" in cmd
    assert "find " not in cmd


# ===========================================================================
# list_virtual_sap_stars — basic shape check (parser is heuristic
# pending real kernel-790 list output)
# ===========================================================================

def test_list_returns_stable_shape_on_empty_output():
    from sap_dpmon_sapstar import list_virtual_sap_stars
    exec_fn = _fake_exec_returning("")
    r = list_virtual_sap_stars(exec_fn, "S4H", "00")
    assert r["success"] is False
    assert r["entries"] == []
    assert "error" in r


def test_list_passes_dpmon_not_found_through():
    from sap_dpmon_sapstar import list_virtual_sap_stars
    exec_fn = _fake_exec_returning("SAPMAP_DPMON_NOT_FOUND\n")
    r = list_virtual_sap_stars(exec_fn, "S4H", "00")
    assert r["success"] is False
    assert "not found" in r["error"].lower()


# ===========================================================================
# delete_virtual_sap_star — basic shape check
# ===========================================================================

def test_delete_rejects_invalid_client():
    from sap_dpmon_sapstar import delete_virtual_sap_star
    exec_fn = _fake_exec_returning("should not be called")
    r = delete_virtual_sap_star(exec_fn, "S4H", "00", "xyz")
    assert r["success"] is False
    assert "invalid client" in r["error"].lower()
    assert exec_fn.calls == []


def test_delete_recognises_success_marker_with_client():
    from sap_dpmon_sapstar import delete_virtual_sap_star
    out = "   Virtual SAP* user in client 001 deleted.\n"
    exec_fn = _fake_exec_returning(out)
    r = delete_virtual_sap_star(exec_fn, "S4H", "00", "001")
    assert r["success"] is True
    assert r["client"] == "001"


def test_delete_classifies_not_found():
    from sap_dpmon_sapstar import delete_virtual_sap_star
    out = "Error: virtual SAP* in client 001 does not exist.\n"
    exec_fn = _fake_exec_returning(out)
    r = delete_virtual_sap_star(exec_fn, "S4H", "00", "001")
    assert r["success"] is False
    assert "did not exist" in r["error"]


# ===========================================================================
# chunked_drop_and_run — workaround for sapxpg PARAMS tokenizer
# ===========================================================================

def _fake_gw_exec_recorder():
    """A fake GwExecFn that records (program, args) calls and replies
    success with empty output (or a per-program-overrideable result).

    Built-in async-friendly behaviour, tuned so ``chunked_drop_and_run``
    completes end-to-end without a real target:

      * ``/bin/cat /etc/hostname`` → returns a hostname line so the
        python3 probe's readback canary succeeds
      * ``/bin/cat`` (any other path) → returns the DONE sentinel so
        the async polling loop exits on the first poll
      * ``/bin/ls /usr/bin/python3`` → returns the path itself so the
        probe's first candidate wins (no need to walk the fallback list)
      * ``/bin/ls`` (any other path) → returns "cannot access" so
        subsequent candidates are rejected

    Tests can override any of these via ``canned["<program>"]`` or the
    more granular ``canned_by_args[(program, args)]``.  ``canned``
    matches by program name only (like before); ``canned_by_args``
    lets tests distinguish e.g. the hostname cat from the result-file
    cat.  When a canned entry exists for both, the argv-specific
    one wins."""
    from sap_dpmon_sapstar import _DONE_SENTINEL
    calls = []
    canned = {}          # {program: dict-result}
    canned_by_args = {}  # {(program, args): dict-result}

    def gw_exec(program, args):
        calls.append((program, args))
        key = (program, args)
        if key in canned_by_args:
            return canned_by_args[key]
        if program in canned:
            return canned[program]
        if program == "/bin/cat":
            # Canary: /etc/hostname must return SOMETHING so the
            # readback-channel-alive check passes.
            if args == "/etc/hostname":
                return {"success": True,
                        "output": ["s4hanadev.example"],
                        "error": ""}
            # Any other cat is treated as a result-file poll — return
            # DONE so the polling loop exits immediately.
            return {"success": True,
                    "output": [_DONE_SENTINEL],
                    "error": ""}
        if program == "/bin/ls":
            # First-candidate python3 discovery: /usr/bin/python3 wins.
            # /hana/shared/ enumeration returns empty (no HDB visible
            # in the fake), so the probe falls back to the ABAP SID
            # branch but /usr/bin/python3 satisfies before any HANA
            # path is tried.
            if args == "/usr/bin/python3":
                return {"success": True,
                        "output": ["/usr/bin/python3"],
                        "error": ""}
            return {"success": True,
                    "output": [f"ls: cannot access '{args}': "
                               f"No such file or directory"],
                    "error": ""}
        # Default: every other program returns success+empty.
        return {"success": True, "output": [], "error": ""}

    gw_exec.calls = calls
    gw_exec.canned = canned
    gw_exec.canned_by_args = canned_by_args
    return gw_exec


def test_chunked_drop_and_run_uses_python3_for_chunks():
    """Each base64 chunk must be written via <python3> -c open(...).write(...)
    — that's the no-shell-metacharacter pattern.

    The exact python3 binary path is DISCOVERED at call time (via
    _probe_python3_via_exec_fn) rather than being hardcoded to bare
    "python3"; the fake recorder makes /usr/bin/python3 the winning
    candidate so we assert on that path here."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    chunked_drop_and_run(gw, "echo hello world | wc -l")
    # Match by suffix so this test survives a change to the candidate
    # list ordering (e.g. if a HANA-shipped path becomes preferred on
    # some future recorder configuration).  Also filter to the write
    # pattern so we don't confuse the b64decode call with a chunk
    # write.
    python_calls = [(p, a) for p, a in gw.calls
                    if p.endswith("python3") and a.startswith("-c open(")
                    and ".write(b'" in a]
    assert python_calls, (
        "Helper must call a discovered python3 binary to drop the "
        "base64 in chunks with the -c open().write() pattern")
    # Each python3 call's args must use the open()/.write() pattern
    for prog, args in python_calls:
        assert args.startswith("-c open("), (
            f"python3 chunk write must use -c open(...): {args!r}")
        assert ".write(b'" in args
        # Base64 alphabet only inside the b'...' literal — no spaces,
        # no shell metacharacters
        m = re.search(r"\.write\(b'([^']*)'\)", args)
        assert m, f"chunk literal not parseable: {args}"
        chunk = m.group(1)
        # Allow base64 chars + padding
        assert re.fullmatch(r"[A-Za-z0-9+/=]*", chunk), (
            f"chunk must contain only base64 chars: {chunk!r}")


def test_chunked_drop_and_run_uses_python3_to_decode():
    """The decode step must reuse the discovered python3 (NOT openssl,
    which is often absent on hardened HANA appliances) via a base64
    one-liner that mirrors the pattern used by the HANA wrapper
    writer in sap_db_sql_writers._write_hana_wrapper_via_gw.

    Regression guard for the "openssl not installed on target"
    silent-failure mode: the previous implementation ran
    /usr/bin/openssl to decode the base64 payload; SAPXPG's
    "launched" ack fired even when openssl was missing, so the .sh
    file was never written and every subsequent SQL step failed
    with 'sh: /tmp/sapmap_dp_XXX.sh: No such file or directory'."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    chunked_drop_and_run(gw, "test command")
    openssl_calls = [c for c in gw.calls if c[0] == "/usr/bin/openssl"]
    assert not openssl_calls, (
        "Helper must NOT invoke openssl any more — "
        "it's frequently missing on hardened SAP hosts")
    py_calls = [(prog, args) for prog, args in gw.calls
                if prog.endswith("python3") and ".sh" in args
                and "base64" in args and "b64decode" in args]
    assert py_calls, (
        "Helper must run one python3 call whose -c one-liner writes "
        "the .sh file via base64.b64decode() of the .b64 blob")
    _prog, args = py_calls[0]
    # Round-trip sanity: parseable structure — .b64 in, .sh out
    assert ".b64" in args and ".sh" in args
    # The .sh path is what /bin/bash will exec — must be the write
    # target of the b64decode expression
    assert "open('/tmp/sapmap_dp_" in args
    assert ".write(__import__('base64').b64decode" in args


def test_chunked_drop_and_run_executes_via_bash_file():
    """The execute step must invoke /bin/bash with a script file path —
    no shell metacharacters in argv.  bash's job is to launch the
    async worker (returns in <1s); the actual command output is
    captured via subsequent /bin/cat polls of the result file."""
    from sap_dpmon_sapstar import chunked_drop_and_run, _DONE_SENTINEL
    gw = _fake_gw_exec_recorder()
    # Simulate the wrapped script having written its output + sentinel
    # to the result file before the first cat poll arrives.
    gw.canned["/bin/cat"] = {
        "success": True,
        "output": [
            "Access unlocked. [client = 000] [validity = 10 min].",
            "Password:",
            "----------------------------------------",
            "ABCDEFGHIJ2345MNOPQRSTUVWXYZ2345MNOPQRST",
            "----------------------------------------",
            _DONE_SENTINEL,
        ],
        "error": "",
    }
    # Speed-poll so the test isn't slowed by the default 2-second
    # poll interval.
    out = chunked_drop_and_run(gw, "anything",
                                poll_seconds=0.0,
                                max_wait_seconds=5.0)
    bash_calls = [c for c in gw.calls if c[0] == "/bin/bash"]
    assert len(bash_calls) == 1, "Exactly one bash launch expected"
    _prog, args = bash_calls[0]
    # args must be just the script path — no flags, no pipes, no quotes
    assert args.startswith("/tmp/sapmap_dp_"), (
        f"bash arg must be the temp script path: {args!r}")
    assert "|" not in args
    assert "'" not in args
    assert '"' not in args
    # The returned string contains the result file contents minus
    # the sentinel (which the helper strips).
    assert "Access unlocked" in out
    assert "ABCDEFGHIJ2345" in out
    assert _DONE_SENTINEL not in out, (
        "The DONE sentinel must be stripped from the returned output")


def test_chunked_drop_and_run_cleans_up_tempfiles():
    """The helper must clean up /tmp/sapmap_dp_* files after running."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    chunked_drop_and_run(gw, "test command")
    rm_calls = [c for c in gw.calls if c[0] == "/bin/rm"]
    assert rm_calls, "Helper must invoke /bin/rm for cleanup"
    # The final rm must remove both .b64 and .sh files
    final_rm = rm_calls[-1]
    assert ".b64" in final_rm[1]
    assert ".sh" in final_rm[1]


def test_chunked_drop_and_run_polls_until_done_sentinel():
    """The helper polls /bin/cat repeatedly until the DONE sentinel
    appears.  Earlier polls (before the worker has written anything)
    must NOT trigger an error — they're just "still running"."""
    from sap_dpmon_sapstar import chunked_drop_and_run, _DONE_SENTINEL

    # Simulate a worker that hasn't written anything on the first 2
    # polls, then writes the result + sentinel on the 3rd poll.
    cat_responses = [
        {"success": True, "output": [], "error": ""},          # poll 1
        {"success": True, "output": ["partial"], "error": ""},  # poll 2
        {"success": True,                                       # poll 3 - done
         "output": ["Access unlocked. [client = 000] [validity = 10 min].",
                    "Password:", "----", "ABCDEFGHIJ2345MNOPQRSTUVWXYZ23",
                    "----", _DONE_SENTINEL],
         "error": ""},
    ]
    cat_idx = [0]

    def gw_exec(program, args):
        if program == "/bin/cat":
            i = cat_idx[0]
            cat_idx[0] += 1
            return cat_responses[min(i, len(cat_responses) - 1)]
        return {"success": True, "output": [], "error": ""}

    out = chunked_drop_and_run(gw_exec, "anything",
                                poll_seconds=0.0,
                                max_wait_seconds=5.0)
    assert "Access unlocked" in out
    assert cat_idx[0] == 3, (
        f"Expected exactly 3 cat polls (2 empty + 1 done); got "
        f"{cat_idx[0]}")


def test_chunked_drop_and_run_raises_on_timeout():
    """If the worker never produces the DONE sentinel before
    max_wait_seconds, the helper must raise RuntimeError with a
    partial-output diagnostic so the operator can see what dpmon
    did emit."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    # Override cat to never return the sentinel — simulate a stuck
    # worker.
    gw.canned["/bin/cat"] = {
        "success": True,
        "output": ["dpmon is hanging on something"],
        "error": "",
    }
    with pytest.raises(RuntimeError) as excinfo:
        chunked_drop_and_run(gw, "anything",
                              poll_seconds=0.01,
                              max_wait_seconds=0.05)
    assert "did not finish" in str(excinfo.value).lower()
    # Partial output must be surfaced in the error
    assert "dpmon is hanging" in str(excinfo.value)


def test_chunked_drop_and_run_raises_on_chunk_failure():
    """If any python3 chunk write fails, the helper must raise
    RuntimeError so the LPE / exploit caller can fall through.

    The recorder's default probe picks /usr/bin/python3 as the
    discovered binary, so we canned-fail the exact path chunk_
    drop_and_run passes back to gw_exec."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    gw.canned["/usr/bin/python3"] = {
        "success": False,
        "output": [],
        "error": "permission denied",
    }
    with pytest.raises(RuntimeError) as excinfo:
        chunked_drop_and_run(gw, "test command")
    assert "chunked write failed" in str(excinfo.value)
    assert "permission denied" in str(excinfo.value)
