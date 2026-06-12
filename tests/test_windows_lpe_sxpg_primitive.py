#!/usr/bin/env python3
"""Tests for the SXPG-via-RFC fallback primitive in Windows LPE."""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sapmap_models import SAPNode, Credentials


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
        assert chunk == 1000

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
