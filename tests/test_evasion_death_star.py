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


def test_launch_omits_pid_flag_when_target_pid_is_none():
    """Default arm should let the C hook auto-attach to ALL workers.
    Julian's find_pids() walks /proc when --pid is absent and hooks
    every disp+work process — critical because SAP round-robins
    dialog sessions across the pool.  If launch always passes --pid,
    only one worker gets hooked and audit events on the others still
    land in SM20 (operator-reported bug)."""
    captured = {}

    def fake_write(node, path, data, label=""):
        # Capture the launcher script content so we can inspect the
        # hook command line embedded in it.
        captured["script"] = data.decode("utf-8", errors="replace")

    def fake_run(node, command, params="", label="", quiet=False):
        if command == "sh" and "/tmp/sapmap_ds_launch" in params:
            return {"success": True,
                     "output": ["STATUS: ALIVE 12345"], "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_death_star._write_remote_file",
                 side_effect=fake_write), \
         patch("sapmap_exploit.run_os_command",
                 side_effect=fake_run):
        pid = sapmap_death_star.launch(
            _mk_node(),
            binary_path="/tmp/sap_audit_hook",
            target_pid=None,        # ← default = all workers
            filter_classes="AUW",
        )
    assert pid == 12345
    script = captured.get("script", "")
    assert "--suppress" in script, "expected --suppress in launcher"
    assert "--pid" not in script, (
        f"launcher must NOT pass --pid when target_pid=None (all-workers "
        f"mode); got script:\n{script}")


def test_launch_includes_pid_flag_when_target_pid_given():
    """When operator supplies a PID explicitly, single-process mode
    is respected — the hook attaches only to that PID."""
    captured = {}

    def fake_write(node, path, data, label=""):
        captured["script"] = data.decode("utf-8", errors="replace")

    def fake_run(node, command, params="", label="", quiet=False):
        if command == "sh" and "/tmp/sapmap_ds_launch" in params:
            return {"success": True,
                     "output": ["STATUS: ALIVE 12345"], "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_death_star._write_remote_file",
                 side_effect=fake_write), \
         patch("sapmap_exploit.run_os_command",
                 side_effect=fake_run):
        sapmap_death_star.launch(
            _mk_node(),
            binary_path="/tmp/sap_audit_hook",
            target_pid=7959,
        )
    script = captured.get("script", "")
    assert "--pid 7959" in script, (
        f"expected --pid 7959 in launcher (single-process mode); "
        f"got script:\n{script}")


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


def test_has_prebuilt_binary_returns_false_when_absent(tmp_path,
                                                          monkeypatch):
    """When the vendored ``sap_audit_hook.linux-x86_64`` is missing,
    ``has_prebuilt_binary()`` returns False so the compile-on-target
    path takes over."""
    monkeypatch.setattr(sapmap_death_star, "HOOK_PREBUILT_PATH",
                         str(tmp_path / "no_such_binary"))
    assert sapmap_death_star.has_prebuilt_binary() is False


def test_has_prebuilt_binary_returns_true_when_present(tmp_path,
                                                          monkeypatch):
    """Real vendored binary present → True."""
    fake = tmp_path / "sap_audit_hook.linux-x86_64"
    fake.write_bytes(b"\x7fELF" + b"\x00" * 200)  # ELF magic + padding
    monkeypatch.setattr(sapmap_death_star, "HOOK_PREBUILT_PATH",
                         str(fake))
    assert sapmap_death_star.has_prebuilt_binary() is True


def test_upload_prebuilt_binary_uploads_and_chmods(tmp_path,
                                                        monkeypatch):
    """The prebuilt-upload path: write file → chmod +x → --help
    verify → return remote path."""
    fake = tmp_path / "sap_audit_hook.linux-x86_64"
    fake.write_bytes(b"\x7fELF" + b"stub" * 100)
    monkeypatch.setattr(sapmap_death_star, "HOOK_PREBUILT_PATH",
                         str(fake))

    calls = []
    raw_len = len(fake.read_bytes())
    import base64 as _b64
    b64_len = len(_b64.b64encode(fake.read_bytes()))

    def fake(node, command, params):
        calls.append((command, params))
        if command == "wc":
            path = params.split()[-1]
            size = b64_len if path.endswith(".b64") else raw_len
            return {"success": True,
                     "output": [f"{size} {path}"], "error": ""}
        if command.endswith("sap_audit_hook") and params == "--help":
            return {"success": True,
                     "output": [
                         "Usage: sap_audit_hook [options]",
                         "  --pid <PID>       target specific disp+work PID",
                         "  --suppress        drop matching audit writes",
                         "  --filter CLASS    only act on these event classes",
                     ],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command", side_effect=fake):
        result = sapmap_death_star.upload_prebuilt_binary(
            _mk_node(), binary_path="/tmp/sap_audit_hook")

    assert result == "/tmp/sap_audit_hook"
    # chmod +x must have been invoked.
    assert any(c[0] == "chmod" and "+x /tmp/sap_audit_hook" in c[1]
                for c in calls), (
        f"chmod +x call not seen; calls={calls}")


def test_upload_prebuilt_rejects_error_containing_binary_name(tmp_path,
                                                                    monkeypatch):
    """Regression: previous loose verify matched error messages that
    contained the binary path, e.g. 'nohup: failed to run command
    /tmp/sap_audit_hook: No such file or directory'."""
    fake = tmp_path / "sap_audit_hook.linux-x86_64"
    fake.write_bytes(b"\x7fELF" + b"stub" * 100)
    monkeypatch.setattr(sapmap_death_star, "HOOK_PREBUILT_PATH",
                         str(fake))

    raw_len = len(fake.read_bytes())
    import base64 as _b64
    b64_len = len(_b64.b64encode(fake.read_bytes()))

    def fake_run(node, command, params):
        if command == "wc":
            path = params.split()[-1]
            size = b64_len if path.endswith(".b64") else raw_len
            return {"success": True,
                     "output": [f"{size} {path}"], "error": ""}
        if command.endswith("sap_audit_hook") and params == "--help":
            return {"success": True,
                     "output": [
                         "nohup: failed to run command "
                         "'/tmp/sap_audit_hook': No such file",
                     ],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}

    with patch("sapmap_exploit.run_os_command", side_effect=fake_run):
        with pytest.raises(sapmap_death_star.DeathStarError,
                            match="--suppress.*--filter"):
            sapmap_death_star.upload_prebuilt_binary(
                _mk_node(), binary_path="/tmp/sap_audit_hook")


def test_upload_prebuilt_rejects_missing_vendored_binary(tmp_path,
                                                              monkeypatch):
    monkeypatch.setattr(sapmap_death_star, "HOOK_PREBUILT_PATH",
                         str(tmp_path / "nonexistent"))
    with pytest.raises(sapmap_death_star.DeathStarError,
                        match="not found"):
        sapmap_death_star.upload_prebuilt_binary(_mk_node())


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
    """When ps fails AND the /proc walk fallback also produces nothing,
    a clear ``no work-processes`` error surfaces."""
    def fake(node, command, params="", label="", quiet=False):
        return {"success": False, "output": [], "error": "SXPG denied"}
    with patch("sapmap_death_star._run", side_effect=fake):
        # Stub _write_remote_file so we don't need to mock all its
        # SXPG round-trips — the writer is exercised elsewhere.
        with patch("sapmap_death_star._write_remote_file"):
            with pytest.raises(sapmap_death_star.DeathStarError,
                                match="no disp\\+work"):
                sapmap_death_star.find_worker_pid(_mk_node())


def test_find_worker_pid_recognises_modern_kernel_750_plus_comm():
    """Regression: operator's S/4 793 target exposed comm as
    ``SAP_S4H_00_W0`` (kernel-750+ format).  Previous version
    required either ``disp+work`` or ``dw.sap`` prefix — modern
    comm has neither — so workers were skipped.  Lock the new
    ``_W\\d+`` suffix classification here."""
    ps_out = [
        "  7948 SAP_S4H_00_DP    dw.sapS4H_D00 pf=/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev",
        "  7959 SAP_S4H_00_W0    dw.sapS4H_D00 pf=/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev",
        "  7960 SAP_S4H_00_W1    dw.sapS4H_D00 pf=/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev",
        "  7973 SAP_S4H_00_W14   dw.sapS4H_D00 pf=/usr/sap/S4H/SYS/profile/S4H_D00_s4hanadev",
    ]
    with patch("sapmap_death_star._run") as mock_run:
        mock_run.return_value = {"success": True, "output": ps_out,
                                  "error": ""}
        pid, comm = sapmap_death_star.find_worker_pid(_mk_node())
    # First dialog worker wins — DP is skipped (dispatcher).
    assert pid == 7959
    assert comm == "SAP_S4H_00_W0"


def test_classify_worker_covers_common_shapes():
    """Direct unit test of the classifier so the two discovery routes
    (ps + /proc walk) agree on what counts as a worker."""
    classify = sapmap_death_star._classify_worker
    # Modern kernel-750+ shapes.
    assert classify("SAP_S4H_00_W0") == "worker"
    assert classify("SAP_S4H_00_W14") == "worker"
    assert classify("SAP_S4H_00_BTC") == "fallback"
    assert classify("SAP_S4H_00_SPO") == "fallback"
    assert classify("SAP_S4H_00_UP2") == "fallback"
    assert classify("SAP_S4H_00_DP") is None  # dispatcher — refused
    # Legacy kernel-≤749 shape.
    assert classify("disp+work") == "fallback"
    assert classify("dw.sapS4H_D00") == "fallback"
    # Non-SAP processes.
    assert classify("bash") is None
    assert classify("systemd") is None


def test_find_worker_pid_falls_back_to_proc_walk_when_ps_empty():
    """When ps returns zero SAP processes (SXPG PATH constraint or a
    non-procps ps variant), the /proc walker script kicks in and
    produces a valid worker PID."""
    def fake(node, command, params="", label="", quiet=False):
        # ps call: no matches.
        if command == "ps":
            return {"success": True, "output": [], "error": ""}
        # /proc walker script: return one dialog worker + one fallback.
        if command == "sh" and "procwalk" in params:
            return {"success": True,
                     "output": ["7959 SAP_S4H_00_W0",
                                "7970 SAP_S4H_00_BTC"],
                     "error": ""}
        return {"success": True, "output": [], "error": ""}
    with patch("sapmap_death_star._run", side_effect=fake):
        with patch("sapmap_death_star._write_remote_file"):
            pid, comm = sapmap_death_star.find_worker_pid(_mk_node())
    assert pid == 7959  # dialog worker preferred
    assert comm == "SAP_S4H_00_W0"


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


def test_death_star_launch_sets_public_hook_pid_flag():
    """After a successful arm, ``node.death_star_hook_pid`` is set to
    the hook PID — the GUI reads this to gate the Disarm menu item.
    Prevents the ``Arm never run → Disarm enabled anyway`` UX bug."""
    state = _armed_state()
    node = _mk_node()
    node._evasion_baseline = {"params": {}}
    assert node.death_star_hook_pid == 0
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
                 return_value=fake_result):
        sapmap_evasion_tier3.tier3_sal_death_star_launch(state, node)
    assert node.death_star_hook_pid == 4900


def test_death_star_stop_clears_public_hook_pid_flag():
    """Paired ``stop`` must clear ``death_star_hook_pid`` so the GUI's
    Disarm menu greys out again after a clean disarm."""
    state = _armed_state()
    node = _mk_node()
    node._evasion_baseline = {"params": {}}
    node.death_star_hook_pid = 4900
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
        sapmap_evasion_tier3.tier3_sal_death_star_stop(state, node)
    assert node.death_star_hook_pid == 0


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
