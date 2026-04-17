"""Tests for sap_java_ctc — /ctc/ConfigServlet client.

All tests are offline. HTTP primitives (_http_get) are monkey-patched.
"""

import base64
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import sap_java_ctc as ctc


# ---------------------------------------------------------------------------
# URL and auth helpers
# ---------------------------------------------------------------------------

class TestHelpers:

    def test_build_url_default_path(self):
        u = ctc._build_url("h", 50000, False)
        assert u == "http://h:50000/ctc/ConfigServlet"

    def test_build_url_custom_path(self):
        u = ctc._build_url("h", 50001, True, path="/foo/Bar")
        assert u == "https://h:50001/foo/Bar"

    def test_build_url_ipv6(self):
        u = ctc._build_url("::1", 50000, False)
        assert u == "http://[::1]:50000/ctc/ConfigServlet"

    def test_auth_header_format(self):
        h = ctc._auth_header("alice", "secret")
        assert h.startswith("Basic ")
        decoded = base64.b64decode(h.split()[1]).decode()
        assert decoded == "alice:secret"

    def test_osexec_wrapper_windows(self):
        w = ctc._osexec_wrapper("echo hi", os_type="windows")
        assert w.startswith("cmd.exe /C ")

    def test_osexec_wrapper_linux(self):
        w = ctc._osexec_wrapper("echo hi", os_type="linux")
        assert w.startswith("/bin/sh -c ")

    def test_strip_html(self):
        assert ctc._strip_html("<p>hello <b>world</b></p>") == "hello world"
        assert ctc._strip_html("") == ""


# ---------------------------------------------------------------------------
# execute_cmd — URL-encoded param construction
# ---------------------------------------------------------------------------

class TestExecuteCmd:

    def test_builds_param_with_execute_cmd(self, monkeypatch):
        captured = {}
        def _fake(url, user, pwd, timeout):
            captured["url"] = url
            return 200, "Success: ok", ""
        monkeypatch.setattr(ctc, "_http_get", _fake)
        r = ctc.execute_cmd("h", 50000, "u", "p", 'cmd.exe /C whoami')
        assert r["success"] is True
        assert "ConfigServlet" in captured["url"]
        assert "EXECUTE_CMD" in captured["url"]
        assert "FileSystemConfig" in captured["url"]

    def test_http_500_is_failure(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (500, "boom", ""))
        r = ctc.execute_cmd("h", 50000, "u", "p", "x")
        assert r["success"] is False
        assert "500" in r["error"]

    def test_network_error_is_failure(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (0, "", "connect refused"))
        r = ctc.execute_cmd("h", 50000, "u", "p", "x")
        assert r["success"] is False
        assert "connect refused" in r["error"]

    def test_error_keyword_in_body_is_failure(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (200, "Error: bad arg", ""))
        r = ctc.execute_cmd("h", 50000, "u", "p", "x")
        assert r["success"] is False

    def test_raw_mode_returns_body_unconditionally(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (200, "Error: nope", ""))
        r = ctc.execute_cmd("h", 50000, "u", "p", "x", raw=True)
        assert r["success"] is True


# ---------------------------------------------------------------------------
# probe — token echo check
# ---------------------------------------------------------------------------

class TestProbe:

    def test_probe_success_echo_token(self, monkeypatch):
        captured_cmds = []
        def _fake_http(url, user, pwd, timeout):
            # Extract CMDLINE from the URL and "execute" it (echo only)
            import urllib.parse as up
            q = up.parse_qs(up.urlparse(url).query)
            param = q.get("param", [""])[0]
            # param looks like: com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=...
            cmd = param.split("CMDLINE=", 1)[-1]
            captured_cmds.append(cmd)
            # The probe sends 'cmd.exe /C echo sapmap_xxxx' — echo it back
            echoed = cmd.split("echo ", 1)[-1] if "echo " in cmd else ""
            return 200, echoed, ""
        monkeypatch.setattr(ctc, "_http_get", _fake_http)
        r = ctc.probe("h", 50000, "u", "p")
        assert r["reachable"] is True
        assert r["authenticated"] is True
        assert "probe token" in r["evidence"].lower()

    def test_probe_404_means_missing(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (404, "", ""))
        r = ctc.probe("h", 50000, "u", "p")
        assert r["reachable"] is True
        assert r["authenticated"] is False
        assert "404" in r["evidence"]

    def test_probe_401_means_auth_rejected(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (401, "", ""))
        r = ctc.probe("h", 50000, "u", "p")
        assert r["authenticated"] is False
        assert "401" in r["evidence"]

    def test_probe_network_error(self, monkeypatch):
        monkeypatch.setattr(ctc, "_http_get",
                             lambda *a, **k: (0, "", "timeout"))
        r = ctc.probe("h", 50000, "u", "p")
        assert r["reachable"] is False


# ---------------------------------------------------------------------------
# discover_ctc_path — alternative endpoint walking
# ---------------------------------------------------------------------------

class TestDiscoverPath:

    def test_returns_first_non_404(self, monkeypatch):
        import urllib.request, urllib.error

        class _FakeResp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): pass

        # Simulate: ConfigServlet 404, CTCWebServiceImpl 200
        calls = []
        def _fake_urlopen(req, timeout, context):
            url = req.full_url
            calls.append(url)
            if "ConfigServlet" in url and "CTCWebServiceImpl" not in url:
                raise urllib.error.HTTPError(url, 404, "", {}, None)
            return _FakeResp()

        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
        found = ctc.discover_ctc_path("h", 50000, "u", "p")
        assert found == "/ctc/CTCWebServiceImpl"

    def test_all_404_returns_empty(self, monkeypatch):
        import urllib.request, urllib.error
        def _always_404(req, timeout, context):
            raise urllib.error.HTTPError(req.full_url, 404, "", {}, None)
        monkeypatch.setattr(urllib.request, "urlopen", _always_404)
        assert ctc.discover_ctc_path("h", 50000, "u", "p") == ""

    def test_auth_gated_401_still_counts_as_present(self, monkeypatch):
        import urllib.request, urllib.error
        def _always_401(req, timeout, context):
            raise urllib.error.HTTPError(req.full_url, 401, "", {}, None)
        monkeypatch.setattr(urllib.request, "urlopen", _always_401)
        # First path in _CTC_ALT_PATHS wins
        assert ctc.discover_ctc_path("h", 50000, "u", "p") == \
            ctc._CTC_ALT_PATHS[0]


# ---------------------------------------------------------------------------
# probe_admin_endpoints — diagnostic
# ---------------------------------------------------------------------------

class TestProbeAdminEndpoints:

    def test_markers_cover_core_cases(self, monkeypatch):
        import urllib.request, urllib.error

        class _FakeResp:
            def __init__(self, s): self.status = s
            def __enter__(self): return self
            def __exit__(self, *a): pass

        # Map path substrings to the status we want to return
        mapping = {
            "/useradmin/": 200,
            "/nwa/": 200,
            "/ctc/ConfigServlet": 404,
            "/monitoring/": 403,
            "/sldc/": 401,
        }
        def _fake_urlopen(req, timeout, context):
            for frag, status in mapping.items():
                if frag in req.full_url:
                    if status == 200:
                        return _FakeResp(200)
                    raise urllib.error.HTTPError(req.full_url, status,
                                                    "", {}, None)
            # default: treat as missing
            raise urllib.error.HTTPError(req.full_url, 404, "", {}, None)
        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

        rows = ctc.probe_admin_endpoints("h", 50000, "u", "p")
        by_path = {r["path"]: r for r in rows}
        assert by_path["/useradmin/"]["marker"] == "OK"
        assert by_path["/nwa/"]["marker"] == "OK"
        assert by_path["/ctc/ConfigServlet"]["marker"] == "MISSING"
        assert by_path["/monitoring/"]["marker"] == "FORBIDDEN"
        assert by_path["/sldc/"]["marker"] == "AUTH-REJECTED"

    def test_unreachable_marker(self, monkeypatch):
        import urllib.request
        def _always_raise(req, timeout, context):
            raise OSError("no route to host")
        monkeypatch.setattr(urllib.request, "urlopen", _always_raise)
        rows = ctc.probe_admin_endpoints("h", 50000, "u", "p")
        assert all(r["marker"] == "UNREACHABLE" for r in rows)
        assert all(r["status"] == 0 for r in rows)


# ---------------------------------------------------------------------------
# deploy_jsp_via_ctc — end-to-end behaviour (discovery + chunked write)
# ---------------------------------------------------------------------------

class TestDeploy:

    def test_no_endpoint_runs_diagnostic_and_fails(self, monkeypatch):
        monkeypatch.setattr(ctc, "discover_ctc_path",
                             lambda *a, **k: "")
        # Bypass probe_admin_endpoints with a harmless stub
        monkeypatch.setattr(ctc, "probe_admin_endpoints",
                             lambda *a, **k: [])
        logs = []
        r = ctc.deploy_jsp_via_ctc("h", 50000, "u", "p",
                                     b"<%=\"x\"%>", "C:\\x.jsp",
                                     log=lambda m: logs.append(m))
        assert r["success"] is False
        assert "no ConfigServlet" in r["error"]

    def test_probe_authenticated_failure_stops_us(self, monkeypatch):
        monkeypatch.setattr(ctc, "discover_ctc_path",
                             lambda *a, **k: "/ctc/ConfigServlet")
        monkeypatch.setattr(ctc, "probe",
                             lambda *a, **k: {"authenticated": False,
                                              "evidence": "401 rejected"})
        r = ctc.deploy_jsp_via_ctc("h", 50000, "u", "p",
                                     b"x", "C:\\x.jsp",
                                     log=lambda m: None)
        assert r["success"] is False
        assert "401 rejected" in r["error"]

    def test_happy_path_writes_chunks_and_decodes(self, monkeypatch):
        monkeypatch.setattr(ctc, "discover_ctc_path",
                             lambda *a, **k: "/ctc/ConfigServlet")
        monkeypatch.setattr(ctc, "probe",
                             lambda *a, **k: {"authenticated": True,
                                              "evidence": "ok"})
        calls = []
        def _fake_exec(host, port, user, pwd, cmd, **kw):
            calls.append(cmd)
            return {"success": True, "error": "", "output": ""}
        monkeypatch.setattr(ctc, "execute_cmd", _fake_exec)
        r = ctc.deploy_jsp_via_ctc("h", 50000, "u", "p",
                                     b"A" * 600, "C:\\x.jsp",
                                     log=lambda m: None)
        assert r["success"] is True
        assert r["bytes_written"] == 600
        # Should see at least one echo + the certutil decode + cleanup
        assert any("echo" in c for c in calls)
        assert any("certutil" in c for c in calls)
