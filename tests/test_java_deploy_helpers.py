"""Tests for Java-deploy helpers in sapmap_exploit.

Covers:
    _parse_telnet_override()
    _candidate_telnet_endpoints()
    _candidate_telnet_ports()
    _resolve_java_admin_creds()
    _telnet_deploy_available()
    _ctc_deploy_available()
    _check_sapmap_user_reusable()

All tests are offline — RFC and TCP probes are monkey-patched.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from sapmap_models import SAPNode, InstanceInfo, CreatedUser
import sapmap_exploit as ex


def _make_java_node(sid="JX1", ip="10.0.0.1", inst_nr="00",
                     java_http=50000,
                     created_users=None,
                     telnet_override="",
                     os_type="Windows"):
    node = SAPNode(sid=sid, hostname=sid.lower(), ip=ip,
                    system_type="JAVA", os_type=os_type)
    inst = InstanceInfo(instance_nr=inst_nr,
                          ports={java_http: "java_http"})
    node.instances = [inst]
    node.cve_2025_31324_port = java_http
    node.telnet_override = telnet_override
    node.created_users = list(created_users or [])
    return node


def _user(method, username="SAPMAP00", password="Pw!"):
    return CreatedUser(username=username, sid="X", client="",
                         hostname="", ip="", instance_nr="00",
                         method=method, password=password)


# ---------------------------------------------------------------------------
# _parse_telnet_override
# ---------------------------------------------------------------------------

class TestParseTelnetOverride:

    def test_empty_returns_blank(self):
        assert ex._parse_telnet_override("") == ("", 0)
        assert ex._parse_telnet_override("   ") == ("", 0)

    def test_host_port(self):
        assert ex._parse_telnet_override("127.0.0.1:50008") == \
            ("127.0.0.1", 50008)

    def test_bare_port(self):
        assert ex._parse_telnet_override("50008") == ("", 50008)

    def test_leading_colon_port(self):
        assert ex._parse_telnet_override(":50008") == ("", 50008)

    def test_invalid_port_returns_blank(self):
        assert ex._parse_telnet_override("abc") == ("", 0)
        assert ex._parse_telnet_override("host:xyz") == ("", 0)

    def test_whitespace_stripped(self):
        assert ex._parse_telnet_override(" 127.0.0.1 : 50008 ") == \
            ("127.0.0.1", 50008)


# ---------------------------------------------------------------------------
# _candidate_telnet_endpoints
# ---------------------------------------------------------------------------

class TestCandidateEndpoints:

    def test_derives_from_java_http_port(self):
        node = _make_java_node(java_http=50000, inst_nr="00")
        eps = ex._candidate_telnet_endpoints(node)
        assert ("10.0.0.1", 50008) in eps

    def test_derives_from_instance_number(self):
        node = _make_java_node(java_http=50100, inst_nr="01")
        eps = ex._candidate_telnet_endpoints(node)
        assert ("10.0.0.1", 50108) in eps

    def test_override_wins_and_is_only_candidate(self):
        node = _make_java_node(telnet_override="127.0.0.1:55555")
        eps = ex._candidate_telnet_endpoints(node)
        assert eps == [("127.0.0.1", 55555)]

    def test_override_port_only_uses_node_host(self):
        node = _make_java_node(telnet_override=":55555")
        eps = ex._candidate_telnet_endpoints(node)
        # When host-part is empty, fall back to node.ip
        assert eps == [("10.0.0.1", 55555)]

    def test_legacy_ports_helper(self):
        node = _make_java_node()
        ports = ex._candidate_telnet_ports(node)
        assert 50008 in ports


# ---------------------------------------------------------------------------
# _resolve_java_admin_creds
# ---------------------------------------------------------------------------

class TestResolveAdminCreds:

    def test_empty_returns_blanks(self):
        node = _make_java_node(created_users=[])
        assert ex._resolve_java_admin_creds(node) == ("", "")

    def test_prefers_java_recon(self):
        node = _make_java_node(created_users=[
            _user("java_cve_31324", username="CVE_U", password="cvepw"),
            _user("java_recon",     username="RECON_U", password="rcnpw"),
        ])
        assert ex._resolve_java_admin_creds(node) == ("RECON_U", "rcnpw")


# ---------------------------------------------------------------------------
# _telnet_deploy_available
# ---------------------------------------------------------------------------

class TestTelnetAvailable:

    def test_non_java_returns_false(self, monkeypatch):
        node = _make_java_node()
        node.system_type = "ABAP"
        assert ex._telnet_deploy_available(node) is False

    def test_requires_admin_user(self, monkeypatch):
        node = _make_java_node(created_users=[])
        assert ex._telnet_deploy_available(node) is False

    def test_port_probe_true_enables(self, monkeypatch):
        node = _make_java_node(created_users=[
            _user("java_recon", password="p"),
        ])
        import sap_java_telnet as _tel
        monkeypatch.setattr(_tel, "probe_port",
                             lambda host, port, timeout=1.5: True)
        assert ex._telnet_deploy_available(node) is True

    def test_all_ports_closed_returns_false(self, monkeypatch):
        node = _make_java_node(created_users=[
            _user("java_recon", password="p"),
        ])
        import sap_java_telnet as _tel
        monkeypatch.setattr(_tel, "probe_port",
                             lambda host, port, timeout=1.5: False)
        assert ex._telnet_deploy_available(node) is False


# ---------------------------------------------------------------------------
# _ctc_deploy_available
# ---------------------------------------------------------------------------

class TestCtcAvailable:

    def test_requires_java_admin(self):
        node = _make_java_node(created_users=[])
        assert ex._ctc_deploy_available(node) is False

    def test_http_port_from_cve_2020_6287(self):
        node = _make_java_node(created_users=[
            _user("java_recon", password="p"),
        ])
        node.cve_2025_31324_port = 0
        node.cve_2020_6287_port = 50000
        assert ex._ctc_deploy_available(node) is True

    def test_falls_back_to_instance_port(self):
        node = _make_java_node(created_users=[
            _user("java_recon", password="p"),
        ])
        node.cve_2025_31324_port = 0
        node.cve_2020_6287_port = 0
        assert ex._ctc_deploy_available(node) is True  # java_http on inst


# ---------------------------------------------------------------------------
# _check_sapmap_user_reusable
# ---------------------------------------------------------------------------

class TestCheckReusable:

    def _stub_details(self, monkeypatch, return_value):
        import sapmap_rfc
        monkeypatch.setattr(sapmap_rfc, "get_user_details",
                             lambda *a, **k: return_value)

    def test_reusable_when_profiles_returned(self, monkeypatch):
        self._stub_details(monkeypatch, {
            "profiles": ["SAP_ALL"], "roles": [],
            "has_sap_all": True, "error": "", "raw": {},
        })
        node = _make_java_node()
        r = ex._check_sapmap_user_reusable(
            node, "SAPMAP00", "pw", "100", "00")
        assert r["reusable"] is True
        assert r["exists"] is True
        assert r["has_sap_all"] is True

    def test_reusable_but_no_sap_all(self, monkeypatch):
        self._stub_details(monkeypatch, {
            "profiles": [], "roles": ["ZSOMETHING"],
            "has_sap_all": False, "error": "", "raw": {},
        })
        node = _make_java_node()
        r = ex._check_sapmap_user_reusable(
            node, "SAPMAP00", "pw", "100", "00")
        assert r["reusable"] is True
        assert r["has_sap_all"] is False

    def test_error_without_data_is_not_reusable(self, monkeypatch):
        self._stub_details(monkeypatch, {
            "profiles": [], "roles": [],
            "has_sap_all": False,
            "error": "RFC_LOGON_FAILURE (Name or password is incorrect)",
            "raw": {},
        })
        node = _make_java_node()
        r = ex._check_sapmap_user_reusable(
            node, "SAPMAP00", "wrong", "100", "00")
        assert r["reusable"] is False
        assert "logon/detail failed" in r["reason"]

    def test_rfc_exception_is_not_reusable(self, monkeypatch):
        import sapmap_rfc
        def _raise(*a, **k):
            raise RuntimeError("network down")
        monkeypatch.setattr(sapmap_rfc, "get_user_details", _raise)
        node = _make_java_node()
        r = ex._check_sapmap_user_reusable(
            node, "SAPMAP00", "pw", "100", "00")
        assert r["reusable"] is False
        assert "network down" in r["reason"]
