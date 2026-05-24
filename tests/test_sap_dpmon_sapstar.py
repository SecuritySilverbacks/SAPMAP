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
    success with empty output (or a per-program-overrideable result)."""
    calls = []
    canned = {}  # {program: dict-result}

    def gw_exec(program, args):
        calls.append((program, args))
        return canned.get(program,
                          {"success": True, "output": [], "error": ""})

    gw_exec.calls = calls
    gw_exec.canned = canned
    return gw_exec


def test_chunked_drop_and_run_uses_python3_for_chunks():
    """Each base64 chunk must be written via python3 -c open(...).write(...)
    — that's the no-shell-metacharacter pattern."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    chunked_drop_and_run(gw, "echo hello world | wc -l")
    python_calls = [c for c in gw.calls if c[0] == "python3"]
    assert python_calls, (
        "Helper must call python3 to drop the base64 in chunks")
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


def test_chunked_drop_and_run_uses_openssl_to_decode():
    """The decode step must use openssl with the -A flag (single-line
    base64 acceptance)."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    chunked_drop_and_run(gw, "test command")
    openssl_calls = [c for c in gw.calls if c[0] == "/usr/bin/openssl"]
    assert openssl_calls, "Helper must invoke /usr/bin/openssl"
    _prog, args = openssl_calls[0]
    assert "enc" in args
    assert "-d" in args
    assert "-base64" in args
    assert "-A" in args, (
        "openssl must use -A for single-line base64 input "
        "(without it, output is silently empty)")


def test_chunked_drop_and_run_executes_via_bash_file():
    """The execute step must invoke /bin/bash with a script file path —
    no shell metacharacters in argv."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    gw.canned["/bin/bash"] = {
        "success": True,
        "output": ["script output line"],
        "error": "",
    }
    out = chunked_drop_and_run(gw, "anything")
    bash_calls = [c for c in gw.calls if c[0] == "/bin/bash"]
    assert len(bash_calls) == 1, "Exactly one bash invocation expected"
    _prog, args = bash_calls[0]
    # args must be just the script path — no flags, no pipes, no quotes
    assert args.startswith("/tmp/sapmap_dp_"), (
        f"bash arg must be the temp script path: {args!r}")
    assert "|" not in args
    assert "'" not in args
    assert '"' not in args
    # The returned string must be the bash output
    assert "script output line" in out


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


def test_chunked_drop_and_run_raises_on_chunk_failure():
    """If any python3 chunk write fails, the helper must raise
    RuntimeError so the LPE / exploit caller can fall through."""
    from sap_dpmon_sapstar import chunked_drop_and_run
    gw = _fake_gw_exec_recorder()
    gw.canned["python3"] = {
        "success": False,
        "output": [],
        "error": "permission denied",
    }
    with pytest.raises(RuntimeError) as excinfo:
        chunked_drop_and_run(gw, "test command")
    assert "chunked write failed" in str(excinfo.value)
    assert "permission denied" in str(excinfo.value)
