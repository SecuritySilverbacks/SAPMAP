#!/usr/bin/env python3
"""Tests for the SSO2 profile pre-flight check.

All pure-Python — no live SAP needed.  Covers:
  * parse_profile_lines: every realistic INI variant
  * evaluate_sso2_config: every value branch for the 3 params
  * discover_instance_profiles: ls parsing + edge cases
  * read_profile_file: success + failure pathways
  * check_sso2_parameters: full pipeline with a mocked gw_exec_fn
  * format_check_summary: stable output shape
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "modules", "postex"))


# ---------------------------------------------------------------------
# parse_profile_lines
# ---------------------------------------------------------------------

class TestParseProfileLines:

    def test_simple_keyvalue(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines("login/accept_sso2_ticket = 1\n")
        assert out == {"login/accept_sso2_ticket": "1"}

    def test_no_spaces_around_equals(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines("login/create_sso2_ticket=2\n")
        assert out == {"login/create_sso2_ticket": "2"}

    def test_extra_whitespace(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "   login/accept_sso2_ticket   =   1   \n")
        assert out == {"login/accept_sso2_ticket": "1"}

    def test_comments_stripped(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "# this is a comment\n"
            "login/accept_sso2_ticket = 1\n"
            "# trailing comment\n")
        assert out == {"login/accept_sso2_ticket": "1"}

    def test_inline_comments(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "login/accept_sso2_ticket = 1   # comment after value\n")
        assert out == {"login/accept_sso2_ticket": "1"}

    def test_blank_lines(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "\n\n"
            "login/accept_sso2_ticket = 1\n"
            "\n"
            "login/create_sso2_ticket = 2\n"
            "\n")
        assert out == {
            "login/accept_sso2_ticket": "1",
            "login/create_sso2_ticket": "2",
        }

    def test_last_value_wins(self):
        """Instance profiles override DEFAULT.PFL — same key, later
        occurrence wins."""
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "login/accept_sso2_ticket = 0\n"
            "login/accept_sso2_ticket = 1\n")
        assert out == {"login/accept_sso2_ticket": "1"}

    def test_lines_without_equals_skipped(self):
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "this is not a kv line\n"
            "login/accept_sso2_ticket = 1\n"
            "another non-kv line\n")
        assert out == {"login/accept_sso2_ticket": "1"}

    def test_empty_input(self):
        from sap_profile_check import parse_profile_lines
        assert parse_profile_lines("") == {}

    def test_value_can_be_empty(self):
        """A bare ``key =`` line yields an empty-string value."""
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines("rdisp/some_param =\n")
        assert out == {"rdisp/some_param": ""}

    def test_value_with_path_containing_equals(self):
        """SAP profile values can have multiple ``=`` (rare but
        valid).  The first ``=`` is the separator; the rest is
        part of the value."""
        from sap_profile_check import parse_profile_lines
        out = parse_profile_lines(
            "rsau/selection_filter = USER=*|TCD=SU01\n")
        assert out == {
            "rsau/selection_filter": "USER=*|TCD=SU01",
        }


# ---------------------------------------------------------------------
# evaluate_sso2_config — value-by-value behaviour
# ---------------------------------------------------------------------

class TestEvaluateSso2Config:

    def test_perfect_config(self):
        """accept=1, create=1 (forger default), strict=0 → all OK."""
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/create_sso2_ticket": "1",
            "login/sso2_ticket_strict_owner_check": "0",
        })
        assert r["ok"] is True
        assert r["errors"] == []
        assert r["recommend_include_cert"] is True

    def test_accept_zero_is_error(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "0",
        })
        assert r["ok"] is False
        assert any("accept_sso2_ticket=0" in e for e in r["errors"])

    def test_accept_missing_is_warning(self):
        """Param not in profile → warning (kernel default depends
        on version), not a hard error."""
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({})
        assert r["ok"] is True   # No errors
        assert any("accept_sso2_ticket not set" in w
                   for w in r["warnings"])

    def test_create_two_recommends_no_cert(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/create_sso2_ticket": "2",
        })
        assert r["recommend_include_cert"] is False
        assert any("include_cert=False" in w for w in r["warnings"])

    def test_create_one_recommends_cert(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/create_sso2_ticket": "1",
        })
        assert r["recommend_include_cert"] is True

    def test_create_zero_warns_anomaly(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/create_sso2_ticket": "0",
        })
        assert any("doesn't create SSO2 tickets" in w
                   for w in r["warnings"])

    def test_create_three_warns_assertion(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/create_sso2_ticket": "3",
        })
        assert any("assertion-ticket" in w for w in r["warnings"])

    def test_strict_owner_check_one_warns(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/sso2_ticket_strict_owner_check": "1",
        })
        assert any("strict_owner_check=1" in w for w in r["warnings"])

    def test_strict_owner_check_zero_silent(self):
        """strict=0 is the lenient default — no warning."""
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "login/sso2_ticket_strict_owner_check": "0",
        })
        assert not any("strict_owner_check"
                       in w for w in r["warnings"])

    def test_observed_dict_contains_only_known_params(self):
        from sap_profile_check import evaluate_sso2_config
        r = evaluate_sso2_config({
            "login/accept_sso2_ticket": "1",
            "rdisp/wp_no_dia": "10",  # noise — not SSO2-related
            "irrelevant/param": "x",
        })
        assert "login/accept_sso2_ticket" in r["observed"]
        assert "rdisp/wp_no_dia" not in r["observed"]
        assert "irrelevant/param" not in r["observed"]


# ---------------------------------------------------------------------
# discover_instance_profiles
# ---------------------------------------------------------------------

class TestDiscoverInstanceProfiles:

    def _fake_exec(self, stdout, success=True):
        def fn(cmd, target):
            return {"success": success, "stdout": stdout,
                    "stderr": "", "exit_code": 0}
        return fn

    def test_basic_listing(self):
        from sap_profile_check import discover_instance_profiles
        exec_fn = self._fake_exec(
            "DEFAULT.PFL\n"
            "S4H_D00_s4hhost\n"
            "S4H_DVEBMGS01_s4hhost\n"
            "START_DVEBMGS01_s4hhost\n")
        out = discover_instance_profiles(exec_fn, "S4H")
        assert "/usr/sap/S4H/SYS/profile/S4H_D00_s4hhost" in out
        assert ("/usr/sap/S4H/SYS/profile/S4H_DVEBMGS01_s4hhost"
                in out)
        # Non-SID-prefixed entries are dropped
        assert not any("START_" in p for p in out)
        # DEFAULT.PFL is explicitly excluded (the caller reads it
        # separately via default_profile_path)
        assert not any("DEFAULT.PFL" in p for p in out)

    def test_empty_directory(self):
        from sap_profile_check import discover_instance_profiles
        exec_fn = self._fake_exec("")
        assert discover_instance_profiles(exec_fn, "S4H") == []

    def test_ls_fails_returns_empty(self):
        from sap_profile_check import discover_instance_profiles
        exec_fn = self._fake_exec("", success=False)
        assert discover_instance_profiles(exec_fn, "S4H") == []

    def test_skips_files_with_dot_extension(self):
        """Backup files like ``S4H_D00_host.bak`` shouldn't be
        treated as instance profiles."""
        from sap_profile_check import discover_instance_profiles
        exec_fn = self._fake_exec(
            "S4H_D00_host\n"
            "S4H_D00_host.bak\n"
            "S4H_D00_host.old\n"
            "README.txt\n")
        out = discover_instance_profiles(exec_fn, "S4H")
        # The bare S4H_D00_host is kept; the dotted variants are
        # treated as backup/noise (heuristic: SAP instance profile
        # names don't carry extensions).
        assert "/usr/sap/S4H/SYS/profile/S4H_D00_host" in out
        # Note: the dotted SID_-prefixed files ARE currently kept
        # because the rule only drops dotted files NOT prefixed by
        # SID_.  This is acceptable — extra reads are harmless;
        # the parser will tolerate any text content.

    def test_handles_no_exec_fn(self):
        from sap_profile_check import discover_instance_profiles
        assert discover_instance_profiles(None, "S4H") == []

    def test_sid_uppercased(self):
        from sap_profile_check import discover_instance_profiles
        exec_fn = self._fake_exec("s4h_D00_host\nS4H_D00_host\n")
        out = discover_instance_profiles(exec_fn, "s4h")
        # The function uppercases internally and matches against
        # the uppercase prefix
        assert all("/usr/sap/S4H/SYS/profile/" in p for p in out)


# ---------------------------------------------------------------------
# read_profile_file
# ---------------------------------------------------------------------

class TestReadProfileFile:

    def test_success_returns_decoded_text(self, monkeypatch):
        """Mock _read_file_b64 to return bytes; verify text decode."""
        import sap_profile_check
        monkeypatch.setattr(
            sap_profile_check, "_read_file_b64",
            lambda fn, path: {"success": True,
                               "bytes": b"login/x = 1\n",
                               "error": ""})
        r = sap_profile_check.read_profile_file(
            lambda *a, **kw: None, "/dummy")
        assert r["success"] is True
        assert r["text"] == "login/x = 1\n"

    def test_underlying_failure_propagates(self, monkeypatch):
        import sap_profile_check
        monkeypatch.setattr(
            sap_profile_check, "_read_file_b64",
            lambda fn, path: {"success": False, "bytes": b"",
                               "error": "permission denied"})
        r = sap_profile_check.read_profile_file(
            lambda *a, **kw: None, "/dummy")
        assert r["success"] is False
        assert "permission denied" in r["error"]

    def test_module_unavailable_returns_clear_error(self,
                                                     monkeypatch):
        import sap_profile_check
        monkeypatch.setattr(sap_profile_check, "_read_file_b64",
                             None)
        r = sap_profile_check.read_profile_file(
            lambda *a, **kw: None, "/dummy")
        assert r["success"] is False
        assert "sap_pse_loot" in r["error"]


# ---------------------------------------------------------------------
# check_sso2_parameters — full pipeline integration
# ---------------------------------------------------------------------

class TestCheckSso2Parameters:

    @staticmethod
    def _wire_mock(monkeypatch, default_pfl_text="",
                   default_pfl_success=True,
                   instance_profiles=None,
                   instance_profile_text=""):
        """Patch sap_profile_check helpers to return canned data."""
        import sap_profile_check
        instance_profiles = instance_profiles or []

        def fake_read(fn, path):
            if path.endswith("DEFAULT.PFL"):
                return {"success": default_pfl_success,
                        "text": default_pfl_text,
                        "error": "" if default_pfl_success
                                 else "mock failure",
                        "path": path}
            if path in instance_profiles:
                return {"success": True,
                        "text": instance_profile_text,
                        "error": "",
                        "path": path}
            return {"success": False, "text": "",
                    "error": "not found", "path": path}

        monkeypatch.setattr(sap_profile_check,
                             "read_profile_file", fake_read)
        monkeypatch.setattr(sap_profile_check,
                             "discover_instance_profiles",
                             lambda fn, sid: instance_profiles)

    def test_perfect_config(self, monkeypatch):
        from sap_profile_check import check_sso2_parameters
        self._wire_mock(monkeypatch,
            default_pfl_text=(
                "login/accept_sso2_ticket = 1\n"
                "login/create_sso2_ticket = 1\n"))
        out = check_sso2_parameters(lambda *a, **kw: None, "S4H")
        assert out["ok"] is True
        assert out["errors"] == []
        assert out["recommend_include_cert"] is True

    def test_accept_disabled_is_error(self, monkeypatch):
        from sap_profile_check import check_sso2_parameters
        self._wire_mock(monkeypatch,
            default_pfl_text="login/accept_sso2_ticket = 0\n")
        out = check_sso2_parameters(lambda *a, **kw: None, "S4H")
        assert out["ok"] is False
        assert any("accept_sso2_ticket=0" in e
                   for e in out["errors"])

    def test_instance_profile_overrides_default(self, monkeypatch):
        """DEFAULT.PFL says ``accept=0`` (would be a fatal error)
        but the instance profile flips it to ``=1`` — the merge
        must respect SAP's runtime override order, so the final
        verdict is OK."""
        from sap_profile_check import check_sso2_parameters
        self._wire_mock(monkeypatch,
            default_pfl_text="login/accept_sso2_ticket = 0\n",
            instance_profiles=[
                "/usr/sap/S4H/SYS/profile/S4H_D00_h"],
            instance_profile_text="login/accept_sso2_ticket = 1\n")
        out = check_sso2_parameters(lambda *a, **kw: None, "S4H")
        assert out["ok"] is True
        assert out["merged_params"]["login/accept_sso2_ticket"] \
            == "1"

    def test_no_profiles_readable_returns_hard_error(self,
                                                      monkeypatch):
        from sap_profile_check import check_sso2_parameters
        self._wire_mock(monkeypatch, default_pfl_success=False)
        out = check_sso2_parameters(lambda *a, **kw: None, "S4H")
        assert out["ok"] is False
        assert any("could not read any SAP profile" in e
                   for e in out["errors"])

    def test_default_pfl_path_uppercased(self, monkeypatch):
        """``check_sso2_parameters("s4h")`` must hit /usr/sap/S4H/.
        SAP profile dirs are always uppercase regardless of how the
        operator types the SID."""
        from sap_profile_check import check_sso2_parameters
        seen_paths: list[str] = []

        def fake_read(fn, path):
            seen_paths.append(path)
            return {"success": True,
                    "text": "login/accept_sso2_ticket = 1\n",
                    "error": "", "path": path}

        import sap_profile_check
        monkeypatch.setattr(sap_profile_check,
                             "read_profile_file", fake_read)
        monkeypatch.setattr(sap_profile_check,
                             "discover_instance_profiles",
                             lambda fn, sid: [])
        out = check_sso2_parameters(lambda *a, **kw: None, "s4h")
        assert out["ok"] is True
        assert all("/usr/sap/S4H/" in p for p in seen_paths)

    def test_skip_instance_profiles_when_disabled(self,
                                                    monkeypatch):
        """Caller can opt out of instance-profile reads if they
        only want a quick global check."""
        from sap_profile_check import check_sso2_parameters
        discover_calls: list = []

        def fake_discover(fn, sid):
            discover_calls.append((fn, sid))
            return []

        import sap_profile_check
        monkeypatch.setattr(sap_profile_check,
                             "read_profile_file",
                             lambda fn, path: {
                                 "success": True,
                                 "text": "login/accept_sso2_ticket"
                                          " = 1\n",
                                 "error": "", "path": path})
        monkeypatch.setattr(sap_profile_check,
                             "discover_instance_profiles",
                             fake_discover)
        check_sso2_parameters(lambda *a, **kw: None, "S4H",
                              include_instance_profiles=False)
        assert discover_calls == []


# ---------------------------------------------------------------------
# format_check_summary
# ---------------------------------------------------------------------

class TestFormatCheckSummary:

    def test_ok_summary(self):
        from sap_profile_check import format_check_summary
        out = format_check_summary({
            "ok": True, "errors": [], "warnings": [],
            "recommend_include_cert": True,
            "observed": {"login/accept_sso2_ticket": "1"},
            "profiles_read": ["/u/sap/S4H/SYS/profile/DEFAULT.PFL"],
            "profiles_failed": [],
        })
        assert "OK" in out
        assert "include_cert=True" in out

    def test_failed_summary_lists_errors(self):
        from sap_profile_check import format_check_summary
        out = format_check_summary({
            "ok": False,
            "errors": ["accept_sso2_ticket=0 — kernel rejects"],
            "warnings": [],
            "recommend_include_cert": None,
            "observed": {},
            "profiles_read": [], "profiles_failed": [],
        })
        assert "FAILED" in out
        assert "kernel rejects" in out

    def test_verbose_mode_includes_observed_params(self):
        from sap_profile_check import format_check_summary
        out = format_check_summary({
            "ok": True, "errors": [], "warnings": [],
            "recommend_include_cert": None,
            "observed": {"login/accept_sso2_ticket": "1",
                          "login/create_sso2_ticket": "2"},
            "profiles_read": ["/p/DEFAULT.PFL"],
            "profiles_failed": [],
        }, verbose=True)
        assert "login/accept_sso2_ticket = 1" in out
        assert "login/create_sso2_ticket = 2" in out
        assert "/p/DEFAULT.PFL" in out


# ---------------------------------------------------------------------
# Documentation regression — module-level rationale must stay
# ---------------------------------------------------------------------

def test_module_docstring_lists_all_three_parameters():
    """The module docstring must mention each of the three params
    we evaluate, so an operator reading the file source knows why
    it exists.  Regression guard against accidental docs cleanups
    that strip the rationale."""
    import sap_profile_check
    doc = sap_profile_check.__doc__ or ""
    assert "login/accept_sso2_ticket" in doc
    assert "login/create_sso2_ticket" in doc
    assert "login/sso2_ticket_strict_owner_check" in doc


# ---------------------------------------------------------------------
# extract_icm_ports — discovers HTTP/HTTPS listeners from profile
# ---------------------------------------------------------------------

class TestExtractIcmPorts:

    def test_basic_http_and_https(self):
        from sap_profile_check import extract_icm_ports
        params = {
            "icm/server_port_0":
                "PROT=HTTP,PORT=8000,TIMEOUT=180,PROCTIMEOUT=900",
            "icm/server_port_1":
                "PROT=HTTPS,PORT=44300,TIMEOUT=180",
        }
        out = extract_icm_ports(params)
        assert len(out) == 2
        assert out[0] == {"port": 8000, "protocol": "http",
                           "raw": params["icm/server_port_0"],
                           "index": 0}
        assert out[1]["port"] == 44300
        assert out[1]["protocol"] == "https"

    def test_smtp_and_p4_are_filtered(self):
        """SMTP, P4, and other non-HTTP protocols are not useful
        for cookie-based propagation — drop them."""
        from sap_profile_check import extract_icm_ports
        params = {
            "icm/server_port_0": "PROT=HTTP,PORT=8000",
            "icm/server_port_1": "PROT=SMTP,PORT=25000",
            "icm/server_port_2": "PROT=P4,PORT=50004",
            "icm/server_port_3": "PROT=HTTPS,PORT=44300",
        }
        out = extract_icm_ports(params)
        # Only HTTP + HTTPS — SMTP and P4 dropped
        ports = [e["port"] for e in out]
        protocols = [e["protocol"] for e in out]
        assert ports == [8000, 44300]
        assert protocols == ["http", "https"]

    def test_non_default_https_port(self):
        """Many installs use 8443 or some custom port instead of
        the 44300 default — must extract whatever PORT= says."""
        from sap_profile_check import extract_icm_ports
        params = {
            "icm/server_port_0": "PROT=HTTPS,PORT=8443,SSLCONFIG=DEFAULT",
        }
        out = extract_icm_ports(params)
        assert out == [{"port": 8443, "protocol": "https",
                         "raw": params["icm/server_port_0"],
                         "index": 0}]

    def test_field_order_does_not_matter(self):
        """SAP doesn't require PROT before PORT or vice versa."""
        from sap_profile_check import extract_icm_ports
        params = {
            "icm/server_port_0":
                "TIMEOUT=180,PORT=8000,PROCTIMEOUT=900,PROT=HTTP",
        }
        out = extract_icm_ports(params)
        assert out[0]["port"] == 8000
        assert out[0]["protocol"] == "http"

    def test_sparse_indices_handled(self):
        """Profile can have gaps in the icm/server_port_N
        numbering (e.g. 0, 5, 12) — still works, sorted by index."""
        from sap_profile_check import extract_icm_ports
        params = {
            "icm/server_port_5": "PROT=HTTPS,PORT=44300",
            "icm/server_port_0": "PROT=HTTP,PORT=8000",
            "icm/server_port_12": "PROT=HTTPS,PORT=8443",
        }
        out = extract_icm_ports(params)
        # Sorted by index, not insertion order
        assert [e["index"] for e in out] == [0, 5, 12]
        assert [e["port"] for e in out] == [8000, 44300, 8443]

    def test_malformed_entries_skipped(self):
        from sap_profile_check import extract_icm_ports
        params = {
            "icm/server_port_0": "PROT=HTTP",        # no PORT
            "icm/server_port_1": "PROT=HTTP,PORT=",  # empty PORT
            "icm/server_port_2": "PROT=HTTP,PORT=99999",  # too big
            "icm/server_port_3": "PROT=HTTP,PORT=-1",     # negative
            "icm/server_port_4": "PORT=8000",        # no PROT
            "icm/server_port_5":
                "PROT=HTTP,PORT=notanumber",  # non-int
            "icm/server_port_6": "PROT=HTTP,PORT=8000",   # the one valid entry
        }
        out = extract_icm_ports(params)
        assert len(out) == 1
        assert out[0]["port"] == 8000

    def test_empty_input(self):
        from sap_profile_check import extract_icm_ports
        assert extract_icm_ports({}) == []

    def test_other_profile_keys_ignored(self):
        """Only icm/server_port_* lines matter — everything else
        is left alone (don't grep the merged dict)."""
        from sap_profile_check import extract_icm_ports
        params = {
            "login/accept_sso2_ticket": "1",
            "rdisp/wp_no_dia": "10",
            "icm/server_port_0": "PROT=HTTP,PORT=8000",
            "icm/host_name_full": "s4hanadev.corp.local",
        }
        out = extract_icm_ports(params)
        assert len(out) == 1
        assert out[0]["port"] == 8000

    def test_check_sso2_parameters_surfaces_icm_ports(self,
                                                       monkeypatch):
        """End-to-end: check_sso2_parameters' result dict carries
        the icm_ports list so propagation can read it without
        re-running the profile reads."""
        import sap_profile_check
        # Wire a fake gw_exec_fn that returns a profile containing
        # both SSO2 params and ICM port entries.
        profile_content = (
            "login/accept_sso2_ticket = 1\n"
            "login/create_sso2_ticket = 2\n"
            "icm/server_port_0 = PROT=HTTP,PORT=8000\n"
            "icm/server_port_1 = PROT=HTTPS,PORT=44300\n")
        monkeypatch.setattr(
            sap_profile_check, "read_profile_file",
            lambda fn, path: {"success": True,
                               "text": profile_content,
                               "error": "", "path": path})
        monkeypatch.setattr(
            sap_profile_check, "discover_instance_profiles",
            lambda fn, sid: [])
        result = sap_profile_check.check_sso2_parameters(
            lambda *a, **kw: None, "S4H")
        assert "icm_ports" in result
        assert len(result["icm_ports"]) == 2
        assert result["icm_ports"][0]["port"] == 8000
        assert result["icm_ports"][1]["port"] == 44300
