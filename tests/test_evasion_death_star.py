"""Tests for the Virtual SAP Death Star (Julian Petersohn) integration.

Covers:
  * Registry: ``sal_death_star`` is a registered Tier 3 technique.
  * Gate: ``tier3_sal_death_star_launch`` refuses when ``--allow-evasion``
    is off; refuses on Windows targets; refuses on non-baselined nodes.
  * Deployment scripter: gzip/base64 payload, shell quoting, worker
    PID selection prefer ``_W<n>``.
  * Vendored source exists on disk.

No real target is spun up — everything is mocked so tests run in the
same environment as the rest of the SAPMAP suite.
"""
from __future__ import annotations

import base64
import os
import re
from unittest.mock import patch, MagicMock

import pytest

from sapmap_models import SAPMAPState, SAPNode
import sapmap_evasion
import sapmap_evasion_gate
import sapmap_evasion_tier3
import sapmap_death_star


# ---------------------------------------------------------------------------
# Vendored source
# ---------------------------------------------------------------------------

def test_vendored_source_exists():
    assert os.path.isfile(sapmap_death_star.HOOK_SOURCE_PATH), (
        f"expected sap_audit_hook.c at "
        f"{sapmap_death_star.HOOK_SOURCE_PATH!r}")


def test_vendored_source_has_expected_shape():
    with open(sapmap_death_star.HOOK_SOURCE_PATH, "rb") as fh:
        head = fh.read(4096)
    assert b"sap_audit_hook" in head
    assert b"ptrace" in head
    # Attribution header
    assert b"Julian Petersohn" in head
    assert b"virtual-sap-death-star" in head


# ---------------------------------------------------------------------------
# Gate registry
# ---------------------------------------------------------------------------

def test_death_star_registered_as_tier3():
    assert "sal_death_star" in sapmap_evasion_gate.TIER3_TECHNIQUES
    t = sapmap_evasion_gate.TIER3_TECHNIQUES["sal_death_star"]
    assert "Death Star" in t.label
    assert t.required_flag == "allow_evasion"


def test_death_star_label_lookup():
    assert "Death Star" in sapmap_evasion_gate.technique_label(
        "sal_death_star")


# ---------------------------------------------------------------------------
# Payload / helpers
# ---------------------------------------------------------------------------

def test_gzip_b64_roundtrip():
    """The payload must decode back to the original bytes so the
    on-target ``base64 -d | gunzip`` produces byte-identical source."""
    import base64
    import gzip
    src = sapmap_death_star._read_source_bytes()
    b64 = sapmap_death_star._gzip_b64(src)
    decoded = gzip.decompress(base64.b64decode(b64))
    assert decoded == src


def test_gzip_b64_compresses_the_source():
    """The whole point of gzipping first is to fit a ~61 KB source
    into a manageable SXPG argv payload.  Sanity check the ratio."""
    src = sapmap_death_star._read_source_bytes()
    b64 = sapmap_death_star._gzip_b64(src)
    # Raw base64 of 61 KB → ~82 KB.  gzip should get us well under that.
    assert len(b64) < len(src) * 0.6, (
        f"gzip+b64 payload ({len(b64)} B) not smaller enough than raw "
        f"source ({len(src)} B) — check gzip level")


# ---------------------------------------------------------------------------
# SXPG-safety invariant — the reason for this whole module's shape
# ---------------------------------------------------------------------------
#
# SAP's SXPG channel splits the ``PARAMS`` field at whitespace and strips
# outer single-quotes.  ``sh -c '<script with spaces>'`` therefore
# collapses into ``sh -c`` (empty argument) and sh dies with
# ``-c: option requires an argument``.  The safe pattern is:
#
#     command = "<no-space executable path>"
#     params  = "<one-or-more space-delimited tokens, no wrapping quotes>"
#
# After ``-c`` in the python3 upload chunks, the payload after the
# single space that separates ``-c`` from the code must be exactly one
# whitespace-free token — no shell metacharacters, no embedded quotes.
#
# These tests lock that invariant on the two failure-prone code paths.

def _mk_upload_fake(raw_len: int):
    """Return a fake ``run_os_command`` that satisfies the size-verify
    steps in ``_write_remote_file`` for a payload of the given raw
    length.  Records every call so tests can inspect the argv shape.
    """
    calls = []
    import base64 as _b64
    b64_len = len(_b64.b64encode(b"X" * raw_len))

    def fake(node, command, params):
        calls.append((command, params))
        if command == "wc":
            # First wc verifies the .b64 scratch (b64 length), second
            # wc verifies the decoded final (raw length).  Look at the
            # path token to know which one is being checked.
            path = params.split()[-1]
            if path.endswith(".b64"):
                size = b64_len
            else:
                size = raw_len
            return {"success": True,
                     "output": [f"{size} {path}"], "error": ""}
        return {"success": True, "output": [], "error": ""}

    return fake, calls


def test_chunk_write_command_has_no_shell_metacharacters():
    """The chunk-write python3 -c payload must be one whitespace-free
    token after ``-c`` — the invariant that SXPG relies on."""
    fake, calls = _mk_upload_fake(300)
    with patch("sapmap_exploit.run_os_command", side_effect=fake):
        sapmap_death_star._write_remote_file(
            _mk_node(), "/tmp/target.dat", b"ABC" * 100,
            label="test upload")

    # Every python3 -c chunk-write call (identified by opening the
    # .b64 scratch for write/append and pasting a raw b'B64' literal)
    # must have zero whitespace in the code portion after ``-c ``.
    # The dpmon-style pattern writes b64 literally (no in-flight
    # decode wrapper) which keeps the PARAMS field well under the
    # 255-char SXPG truncation limit.
    chunk_calls = [
        c for c in calls
        if c[0] == "python3"
        and "open('/tmp/target.dat.b64','wb').write(b'" in c[1]
        or "open('/tmp/target.dat.b64','ab').write(b'" in c[1]
    ]
    assert chunk_calls, "expected at least one python3 chunk write"
    for cmd, params in chunk_calls:
        assert params.startswith("-c "), (
            f"chunk params must start with '-c ', got {params[:40]!r}")
        code = params[len("-c "):]
        assert not any(ws in code for ws in (" ", "\t", "\n")), (
            f"python3 code portion contains whitespace: {code[:80]!r}")
        # The dpmon pattern writes b'B64' literally, no wrapper — the
        # code should NOT include base64.b64decode inline.  Locks the
        # PARAMS budget so future edits don't push chunks back over
        # the SXPG truncation limit.
        assert "b64decode" not in code, (
            f"chunk write must not decode in-flight (PARAMS budget): "
            f"got {code[:120]!r}")


def test_chunk_write_params_stay_under_sxpg_255_char_cap():
    """The reason we switched to the write-then-decode-once pattern:
    each chunk-write PARAMS field must fit in the SXPG PARAMS cap
    (~255 chars on older kernels).  Lock the budget here so future
    edits to the code template don't push us back over."""
    fake, calls = _mk_upload_fake(1519)
    with patch("sapmap_exploit.run_os_command", side_effect=fake):
        # A realistic-length target path — the death star install
        # dir is /tmp so paths run about 30-40 chars.
        sapmap_death_star._write_remote_file(
            _mk_node(), "/tmp/sapmap_ds_stop_ezjdkeva.sh",
            b"X" * 1519, label="length test")

    chunk_calls = [
        c for c in calls
        if c[0] == "python3"
        and ("open('/tmp/sapmap_ds_stop_ezjdkeva.sh.b64','wb')" in c[1]
              or "open('/tmp/sapmap_ds_stop_ezjdkeva.sh.b64','ab')" in c[1])
    ]
    assert chunk_calls, "expected chunk writes"
    for cmd, params in chunk_calls:
        # The full PARAMS field (as sent to SXPG) is what matters for
        # the truncation cap.  ``-c `` prefix + one code token.
        assert len(params) <= 255, (
            f"chunk PARAMS length {len(params)} exceeds 255-char SXPG "
            f"cap — chunks WILL be truncated in transit.  Code: "
            f"{params[:120]!r}…")


def test_upload_raises_on_scratch_size_mismatch():
    """When the b64 scratch verify shows a mismatch, ``_write_remote_file``
    must raise so the operator sees the SXPG truncation cause — not a
    confused shell error 30 s later."""
    def fake(node, command, params):
        if command == "wc":
            # Report a scratch b64 size shorter than expected — simulates
            # a chunk getting truncated in transit.
            path = params.split()[-1]
            return {"success": True,
                     "output": [f"5 {path}"],  # obviously wrong
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command", side_effect=fake):
        with pytest.raises(sapmap_death_star.DeathStarError,
                            match="size mismatch"):
            sapmap_death_star._write_remote_file(
                _mk_node(), "/tmp/x.sh", b"Y" * 500,
                label="corruption test")


def test_launcher_script_dropped_then_invoked_with_two_token_argv(tmp_path):
    """Confirm the launch path uses the file-drop pattern (no ``sh -c``
    with a big scripted-string that SXPG would mangle).  The final
    invocation must be ``sh /tmp/xxx.sh`` — two tokens, no quoting."""
    calls = []

    def fake_run_os_command(node, command, params):
        calls.append((command, params))
        # Simulate the launcher printing the tagged STATUS line the
        # parser now looks for.
        if command == "sh" and params.startswith("/tmp/sapmap_ds_launch"):
            return {"success": True,
                     "output": ["STATUS: ALIVE 12345"],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command",
                 side_effect=fake_run_os_command):
        pid = sapmap_death_star.launch(
            _mk_node(),
            binary_path="/tmp/sap_audit_hook",
            target_pid=4712,
            filter_classes="AUW",
        )
    assert pid == 12345

    # There must be exactly one ``sh <path>`` call — the actual launcher
    # invocation.  ``sh`` command, single-path params → SXPG-safe.
    sh_calls = [c for c in calls if c[0] == "sh"]
    assert len(sh_calls) == 1, (
        f"expected 1 sh call, got {len(sh_calls)}: {sh_calls}")
    _, sh_params = sh_calls[0]
    # ``params`` must be exactly the script path — no ``-c``, no spaces.
    assert sh_params.startswith("/tmp/sapmap_ds_launch_"), sh_params
    assert " " not in sh_params, (
        f"sh params must be a single path token, got {sh_params!r}")


def test_launch_raises_when_hook_dies_within_1s():
    """The launcher's ``STATUS: DIED`` case (usually ptrace_scope > 1
    or an invalid target PID) must surface as a clear operator error,
    not a bare 'launch failed'."""
    def fake_run_os_command(node, command, params):
        if command == "sh" and params.startswith("/tmp/sapmap_ds_launch"):
            return {"success": True,
                     "output": ["DIAG: hook process exited within 1s "
                                "— check /tmp/sap_audit_hook.log for "
                                "ptrace_scope/attach errors",
                                "STATUS: DIED 12345"],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command",
                 side_effect=fake_run_os_command):
        with pytest.raises(sapmap_death_star.DeathStarError,
                            match="ptrace_scope"):
            sapmap_death_star.launch(
                _mk_node(),
                binary_path="/tmp/sap_audit_hook",
                target_pid=4712,
            )


def test_stop_refuses_kernel_pid_from_stale_pidfile():
    """PID 2 (kthreadd) is exactly the failure the operator reported.
    The remote stopper script validates the PID before signaling; here
    we simulate the shell-level sanity check reporting the stale PID
    and confirm the Python parser reads it back as ``NOT_RUNNING``
    (not as a hook-still-running error)."""
    def fake_run_os_command(node, command, params):
        if command == "sh" and params.startswith("/tmp/sapmap_ds_stop"):
            # Shell script detected PID 2 in the pidfile, refused to
            # signal it, cleaned up the stale pidfile, reported
            # NOT_RUNNING.
            return {"success": True,
                     "output": ["DIAG: pidfile=/tmp/sap_audit_hook.pid "
                                "contents=[2]",
                                "DIAG: stale-pid-too-low src=pidfile "
                                "pid=2",
                                "STATUS: NOT_RUNNING"],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command",
                 side_effect=fake_run_os_command):
        r = sapmap_death_star.stop(_mk_node())
    assert r["ok"] is False
    assert r["pid"] is None
    assert "nothing to stop" in r["message"]


def test_stop_status_parser_ignores_diag_line_digits():
    """Regression: previously the stopper joined all output lines with
    spaces and grabbed ``split()[-1]`` as the PID.  DIAG lines contain
    digits (``pid=2``, ``contents=[2]``); if we accidentally parse
    them as PID we'd report ``STILL_RUNNING PID 2`` instead of the
    real STOPPED status.  Lock the tagged-line parser here."""
    def fake_run_os_command(node, command, params):
        if command == "sh" and params.startswith("/tmp/sapmap_ds_stop"):
            return {"success": True,
                     "output": ["DIAG: pidfile=/tmp/sap_audit_hook.pid "
                                "contents=[4900]",
                                "DIAG: sending SIGTERM src=pidfile "
                                "pid=4900 comm=sap_audit_hook",
                                "STATUS: STOPPED 4900"],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command",
                 side_effect=fake_run_os_command):
        r = sapmap_death_star.stop(_mk_node())
    assert r["ok"] is True
    assert r["pid"] == 4900


def test_filter_classes_rejects_shell_metacharacters():
    """The launch path won't accept a filter with anything but
    ``[A-Z0-9,]``.  Prevents an operator smuggling shell metacharacters
    (``;``, backticks, etc.) into the launcher script."""
    with patch("sapmap_exploit.run_os_command",
                 return_value={"success": True, "output": [],
                                "error": ""}):
        with pytest.raises(sapmap_death_star.DeathStarError,
                            match="invalid filter_classes"):
            sapmap_death_star.launch(
                _mk_node(),
                binary_path="/tmp/sap_audit_hook",
                target_pid=4712,
                filter_classes="AUW; rm -rf /",
            )


# ---------------------------------------------------------------------------
# find_worker_pid — prefer _W<n>, fall back to BTC/SPO/UP2
# ---------------------------------------------------------------------------

def _mk_node(sid="S4H", os_type="Linux"):
    return SAPNode(sid=sid, hostname="s4hanadev", ip="192.168.2.209",
                    os_type=os_type)


def test_find_worker_pid_prefers_dialog_worker():
    ps_out = [
        "  4711 dw.sapS4H_D00_DP dispatcher",
        "  4712 dw.sapS4H_D00_W0 worker 0",
        "  4713 dw.sapS4H_D00_W1 worker 1",
        "  4714 dw.sapS4H_D00_BTC batch",
    ]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        pid, comm = sapmap_death_star.find_worker_pid(_mk_node())
    assert pid == 4712
    assert comm.endswith("_W0")


def test_find_worker_pid_falls_back_to_btc_when_no_dialog():
    ps_out = [
        "  5001 dw.sapS4H_D00_DP dispatcher",
        "  5002 dw.sapS4H_D00_BTC batch",
        "  5003 dw.sapS4H_D00_SPO spool",
    ]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        pid, comm = sapmap_death_star.find_worker_pid(_mk_node())
    # First non-dispatcher wins the fallback.
    assert pid == 5002
    assert comm.endswith("_BTC")


def test_find_worker_pid_refuses_dispatcher():
    ps_out = ["  6001 dw.sapS4H_D00_DP dispatcher only"]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        with pytest.raises(sapmap_death_star.DeathStarError):
            sapmap_death_star.find_worker_pid(_mk_node())


def test_find_worker_pid_raises_when_ps_fails():
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": False, "output": [],
                                  "error": "SXPG denied"}
        with pytest.raises(sapmap_death_star.DeathStarError,
                            match="ps failed"):
            sapmap_death_star.find_worker_pid(_mk_node())


# ---------------------------------------------------------------------------
# Tier 3 entry point — gate + OS guard
# ---------------------------------------------------------------------------

def _armed_state():
    state = SAPMAPState()
    state.evasion = {
        "allow_evasion": True,
        "baseline_captured_at": "2026-07-07T08:00:00",
        "diag_terminal_name": "",
        "os_exec_channel": "",
        "mysapsso2_users": "",
        "updated_at": "2026-07-07T08:00:00",
    }
    return state


def test_death_star_launch_refuses_without_evasion_arm():
    state = SAPMAPState()  # allow_evasion defaults False
    node = _mk_node()
    node._evasion_baseline = {"params": {"rsau/enable": "1"}}
    r = sapmap_evasion_tier3.tier3_sal_death_star_launch(state, node)
    assert r["ok"] is False
    assert "allow-evasion" in r["error"].lower() or (
        "not armed" in r["error"].lower())


def test_death_star_launch_refuses_on_windows_target():
    state = _armed_state()
    node = _mk_node(os_type="Windows NT")
    node._evasion_baseline = {"params": {}}
    r = sapmap_evasion_tier3.tier3_sal_death_star_launch(state, node)
    assert r["ok"] is False
    # The OS reason should mention Linux since that's the barrier.
    assert "windows" in r["error"].lower() or "linux" in r["error"].lower()


def test_death_star_launch_calls_deploy_when_armed():
    state = _armed_state()
    node = _mk_node()
    node._evasion_baseline = {"params": {}}

    fake_result = {
        "ok": True,
        "source_path": "/tmp/sap_audit_hook.c",
        "binary_path": "/tmp/sap_audit_hook",
        "target_pid": 4712,
        "target_comm": "dw.sapS4H_D00_W0",
        "hook_pid": 4900,
        "log_path": "/tmp/sap_audit_hook.log",
        "pidfile_path": "/tmp/sap_audit_hook.pid",
        "filter_classes": "AUW",
    }
    with patch("sapmap_death_star.deploy_and_launch",
                 return_value=fake_result) as mock_deploy:
        r = sapmap_evasion_tier3.tier3_sal_death_star_launch(
            state, node, filter_classes="AUW")
    mock_deploy.assert_called_once()
    assert r["ok"] is True
    assert r["hook_pid"] == 4900
    assert r["target_pid"] == 4712
    # Node state should be stashed for a paired stop.
    assert node._death_star_state["hook_pid"] == 4900
    assert node._death_star_state["filter_classes"] == "AUW"


def test_death_star_stop_removes_state_on_success():
    state = _armed_state()
    node = _mk_node()
    node._evasion_baseline = {"params": {}}
    node._death_star_state = {
        "hook_pid": 4900,
        "target_pid": 4712,
        "target_comm": "dw.sapS4H_D00_W0",
        "binary_path": "/tmp/sap_audit_hook",
        "pidfile_path": "/tmp/sap_audit_hook.pid",
        "log_path": "/tmp/sap_audit_hook.log",
        "filter_classes": "AUW",
    }
    with patch("sapmap_death_star.stop",
                 return_value={"ok": True, "pid": 4900,
                               "message": "stopped cleanly"}):
        r = sapmap_evasion_tier3.tier3_sal_death_star_stop(state, node)
    assert r["ok"] is True
    assert not hasattr(node, "_death_star_state")


def test_death_star_stop_is_idempotent_when_nothing_running():
    state = _armed_state()
    node = _mk_node()
    with patch("sapmap_death_star.stop",
                 return_value={"ok": False, "pid": None,
                               "message": "no hook process found — "
                                          "nothing to stop"}):
        r = sapmap_evasion_tier3.tier3_sal_death_star_stop(state, node)
    # Not-running is reported as ok=False but shouldn't raise / clobber
    # any node state.
    assert r["ok"] is False
    assert "nothing to stop" in (r.get("message") or "")
