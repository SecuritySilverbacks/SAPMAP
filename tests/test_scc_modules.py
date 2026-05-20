#!/usr/bin/env python3
"""Tests for the SAP Cloud Connector modules.

Strategy:
  * Pure functions (CVE buckets, mapping normalisation, URL helpers)
    are exercised with hand-crafted inputs.
  * Backup-zip / users-xml parsing is covered by **synthetic fixtures**
    built in-memory so the suite runs anywhere.
  * Where real loot from a previous live run is available under
    ``loot/scc/...``, additional integration tests load it and skip
    cleanly otherwise — these guard regressions on the developer's
    machine without making the suite dependent on uncommitted data.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import pathlib
import zipfile

from unittest.mock import patch

import pytest


_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ===========================================================================
# 1. sapmap_scc_cve_buckets — pure version → CVE lookup
# ===========================================================================

def test_cve_parse_handles_two_three_four_part_versions():
    from sapmap_scc_cve_buckets import _parse
    assert _parse("2.16") == (2, 16)
    assert _parse("2.16.0") == (2, 16, 0)
    assert _parse("2.16.0.1") == (2, 16, 0, 1)
    # Non-numeric tail is dropped, digits are kept
    assert _parse("2.16.0-rc1") == (2, 16, 0, 1)
    assert _parse("") == ()


def test_cve_parse_no_digits_returns_empty():
    from sapmap_scc_cve_buckets import _parse
    assert _parse("garbage") == ()


def test_cves_for_version_in_affected_window():
    """SCC 2.10.x must surface CVE-2024-25642 (TLS validation flaw)."""
    from sapmap_scc_cve_buckets import cves_for_version
    cves = cves_for_version("2.10.0")
    assert len(cves) == 1
    e = cves[0]
    assert e["cve"] == "CVE-2024-25642"
    assert e["severity"] == "HIGH"
    assert e["status"] == "suspected"
    assert e["ref"].endswith("CVE-2024-25642")


def test_cves_for_version_post_patch_returns_empty():
    """SCC 2.16.2 (the patch level) and 2.17.0 must NOT match."""
    from sapmap_scc_cve_buckets import cves_for_version
    assert cves_for_version("2.16.2") == []
    assert cves_for_version("2.17.0") == []


def test_cves_for_version_unknown_returns_empty():
    """Empty / unparseable version must return [] rather than crash."""
    from sapmap_scc_cve_buckets import cves_for_version
    assert cves_for_version("") == []
    assert cves_for_version("not-a-version") == []


def test_score_default_status_is_suspected_no_bundle():
    from sapmap_scc_cve_buckets import score
    out = score("2.10.0", bundle_hash="")
    assert "CVE-2024-25642" in out["suspected"]
    assert out["confirmed"] == []
    assert len(out["details"]) == 1
    assert out["details"][0]["status"] == "suspected"


def test_score_no_bundle_no_promotion():
    """Empty bundle_hash must never produce confirmed entries."""
    from sapmap_scc_cve_buckets import score
    out = score("2.10.0")
    assert out["confirmed"] == []


def test_all_known_cves_listed():
    from sapmap_scc_cve_buckets import all_known_cves
    ids = list(all_known_cves())
    assert "CVE-2024-25642" in ids


# ===========================================================================
# 2. sapmap_scc_admin._normalize_mapping — pure dict transformer
# ===========================================================================

def test_normalize_mapping_v1_config_api_form():
    """v1 config API uses virtualHost/virtualPort/localHost/localPort."""
    from sapmap_scc_admin import _normalize_mapping
    raw = {
        "virtualHost": "myhost.virtual",
        "virtualPort": "8443",
        "localHost":   "10.0.0.5",
        "localPort":   "443",
        "protocol":    "HTTPS",
        "backendType": "abapSys",
        "authenticationMode": "X509_GENERAL",
        "sid":               "S4H",
        "totalResourcesCount":   "12",
        "enabledResourcesCount": "9",
    }
    out = _normalize_mapping(raw)
    assert out["virtual_host"] == "myhost.virtual"
    assert out["virtual_port"] == 8443
    assert out["internal_host"] == "10.0.0.5"
    assert out["internal_port"] == 443
    assert out["protocol"] == "HTTPS"
    assert out["sid"] == "S4H"
    assert out["principal_propagation"] is True   # X509_GENERAL → True
    assert out["authentication_mode"] == "X509_GENERAL"
    assert out["total_resources"] == 12
    assert out["enabled_resources"] == 9


def test_normalize_mapping_legacy_monitor_form():
    """legacy fields virtualUrl/internalHost/internalPort/type still work."""
    from sapmap_scc_admin import _normalize_mapping
    raw = {
        "virtualUrl":   "legacy.virtual",
        "virtualPort":  "443",
        "internalHost": "192.168.1.10",
        "internalPort": "8000",
        "type":         "HTTP",
    }
    out = _normalize_mapping(raw)
    assert out["virtual_host"] == "legacy.virtual"
    assert out["internal_host"] == "192.168.1.10"
    assert out["internal_port"] == 8000
    assert out["protocol"] == "HTTP"
    assert out["principal_propagation"] is False


def test_normalize_mapping_principal_propagation_kerberos():
    """KERBEROS auth must set principal_propagation True."""
    from sapmap_scc_admin import _normalize_mapping
    raw = {"authenticationMode": "KERBEROS"}
    out = _normalize_mapping(raw)
    assert out["principal_propagation"] is True


def test_normalize_mapping_returns_full_shape_on_empty_input():
    """Callers always index by all keys — empty input must still produce
    a complete dict shape."""
    from sapmap_scc_admin import _normalize_mapping
    out = _normalize_mapping({})
    for key in ("virtual_host", "virtual_port", "internal_host",
                "internal_port", "protocol", "path_allowlist",
                "path_wildcards", "backend_type", "principal_propagation",
                "authentication_mode", "sid", "host_in_header",
                "description", "total_resources", "enabled_resources"):
        assert key in out, f"missing key: {key}"


# ===========================================================================
# 3. sapmap_scc_admin._path_for_link — URL helper
# ===========================================================================

def test_path_for_link_strips_matching_base_url():
    from sapmap_scc_admin import _path_for_link
    assert _path_for_link(
        "https://scc.example.com:8443/api/v1/configuration/subaccounts",
        "https://scc.example.com:8443",
    ) == "/api/v1/configuration/subaccounts"


def test_path_for_link_handles_other_host():
    """Absolute URL pointing at a different host: extract just the path."""
    from sapmap_scc_admin import _path_for_link
    out = _path_for_link("https://other.host/foo/bar", "https://scc:8443")
    assert out.startswith("/foo")


def test_path_for_link_relative_input_unchanged():
    from sapmap_scc_admin import _path_for_link
    assert _path_for_link("/api/x", "https://scc:8443") == "/api/x"
    # relative without leading slash gets one prepended
    assert _path_for_link("api/x", "https://scc:8443") == "/api/x"


def test_path_for_link_empty_input():
    from sapmap_scc_admin import _path_for_link
    assert _path_for_link("", "https://scc:8443") == ""


# ===========================================================================
# 4. sapmap_scc_keystore.parse_backup — synthetic minimal zip
# ===========================================================================

def _build_minimal_scc_zip(*, with_ssfs=True, with_users_xml=True,
                            with_subaccount=True) -> bytes:
    """Construct an in-memory zip resembling a real SCC backup."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json",
                    json.dumps({"version": "2.16.0.1",
                                 "filesCRC": {"esalt.bin": 12345}}))
        zf.writestr("config/ks.p12", b"FAKE_UI_KEYSTORE")
        zf.writestr("scc_config/scc.p12", b"FAKE_SYS_KEYSTORE")
        if with_subaccount:
            zf.writestr(
                "scc_config/cf.eu10.hana.ondemand.com/"
                "29aae562-bffb-4e82-9ee5-6e0d4f5f7070/scc.p12",
                b"FAKE_SUB_KEYSTORE")
        if with_ssfs:
            zf.writestr("scc_config/SSFS_SCC.KEY", b"FAKE_SSFS_KEY")
            zf.writestr("scc_config/SSFS_SCC.DAT", b"FAKE_SSFS_DAT")
        if with_users_xml:
            zf.writestr("config/users.xml",
                        b'<?xml version="1.0"?><tomcat-users/>')
    return bio.getvalue()


def test_parse_backup_synthetic_full_layout():
    from sapmap_scc_keystore import parse_backup
    out = parse_backup(_build_minimal_scc_zip())
    assert out["ok"] is True
    assert out["system_keystore"]["path"] == "scc_config/scc.p12"
    assert out["ui_keystore"]["path"] == "config/ks.p12"
    assert len(out["tunnel_keystores"]) == 1
    assert out["tunnel_keystores"][0]["region"] == "cf.eu10.hana.ondemand.com"
    assert out["tunnel_keystores"][0]["subaccount"] == \
        "29aae562-bffb-4e82-9ee5-6e0d4f5f7070"
    assert out["ssfs_present"] is True
    assert out["users_xml_present"] is True
    assert out["users_xml_sha256"]   # populated, non-empty
    assert out["manifest"]["version"] == "2.16.0.1"


def test_parse_backup_missing_ssfs():
    from sapmap_scc_keystore import parse_backup
    out = parse_backup(_build_minimal_scc_zip(with_ssfs=False))
    assert out["ok"] is True
    assert out["ssfs_present"] is False


def test_parse_backup_missing_users_xml():
    from sapmap_scc_keystore import parse_backup
    out = parse_backup(_build_minimal_scc_zip(with_users_xml=False))
    assert out["users_xml_present"] is False
    assert out["users_xml_sha256"] == ""


def test_parse_backup_no_subaccounts():
    from sapmap_scc_keystore import parse_backup
    out = parse_backup(_build_minimal_scc_zip(with_subaccount=False))
    assert out["tunnel_keystores"] == []


def test_parse_backup_invalid_zip_returns_error():
    from sapmap_scc_keystore import parse_backup
    out = parse_backup(b"not a zip at all")
    assert out["ok"] is False
    assert "not a zip" in out["error"]


def test_parse_backup_sha256_stable():
    """Same content → same sha256 across calls."""
    from sapmap_scc_keystore import parse_backup
    z = _build_minimal_scc_zip()
    a = parse_backup(z)
    b = parse_backup(z)
    assert a["system_keystore"]["sha256"] == b["system_keystore"]["sha256"]
    # And matches a hash we can compute independently
    expected = hashlib.sha256(b"FAKE_SYS_KEYSTORE").hexdigest()
    assert a["system_keystore"]["sha256"] == expected


# ---------------------------------------------------------------------------
# Opt-in: real-loot integration — only runs when there's a backup zip on disk
# ---------------------------------------------------------------------------

def _find_real_backup_zip():
    """Return the first real SCC backup zip in loot/, or None."""
    for base in (_PROJECT_ROOT / "loot", _PROJECT_ROOT / "loot" / "old"):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("scc_backup_*.zip")):
            if path.is_file() and path.stat().st_size > 100:
                return path
    return None


_REAL_ZIP = _find_real_backup_zip()


@pytest.mark.skipif(_REAL_ZIP is None,
                    reason="no real SCC backup zip available in loot/")
def test_parse_backup_real_loot_zip():
    """Sanity-check a captured backup against the structure parser."""
    from sapmap_scc_keystore import parse_backup
    out = parse_backup(_REAL_ZIP.read_bytes())
    assert out["ok"] is True, f"failed on {_REAL_ZIP.name}: {out.get('error')}"
    # Real SCC backup ALWAYS has a system keystore + SSFS pair
    assert out["system_keystore"] is not None
    assert out["ssfs_present"] is True
    # Manifest must declare a version
    assert "version" in out["manifest"]


# ===========================================================================
# 5. sapmap_scc_keystore.parse_user_hashes_from_xml — synthetic Tomcat XML
# ===========================================================================

def _ssha_pw(plain_pw: str, salt: bytes) -> str:
    """Build a Tomcat {SSHA} value: base64(sha1(pw+salt) + salt)."""
    h = hashlib.sha1(plain_pw.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(h + salt).decode()


def _sha_pw(plain_pw: str) -> str:
    """Build a Tomcat {SHA} value: base64(sha1(pw))."""
    return "{SHA}" + base64.b64encode(hashlib.sha1(plain_pw.encode()).digest()).decode()


def _sha256_pw(plain_pw: str) -> str:
    return ("{SHA-256}"
            + base64.b64encode(hashlib.sha256(plain_pw.encode()).digest()).decode())


def test_parse_user_hashes_tomcat_sha():
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    pw = _sha_pw("admin123")
    xml = (
        b'<?xml version="1.0"?>\n'
        b'<tomcat-users>'
        b'<user username="Administrator" password="' + pw.encode()
        + b'" roles="sccAdministrator"/>'
        b'</tomcat-users>'
    )
    out = parse_user_hashes_from_xml(xml)
    assert out.get("ok") is not False  # may be {ok:False, ...} on failure
    users = out.get("users") if isinstance(out, dict) else []
    assert len(users) == 1
    u = users[0]
    assert u["username"] == "Administrator"
    assert "SHA-1" in u.get("algorithm", "")


def test_parse_user_hashes_tomcat_ssha():
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    salt = b"ABCD"
    pw = _ssha_pw("secret", salt)
    xml = (
        b'<?xml version="1.0"?>\n'
        b'<tomcat-users>'
        b'<user username="alice" password="' + pw.encode()
        + b'" roles="sccAdministrator"/>'
        b'</tomcat-users>'
    )
    out = parse_user_hashes_from_xml(xml)
    users = out.get("users") if isinstance(out, dict) else []
    assert len(users) == 1
    u = users[0]
    assert u["username"] == "alice"
    algo = u.get("algorithm", "")
    assert "salted" in algo.lower() or "SHA-1" in algo
    # Salt bytes should round-trip as hex
    assert u.get("salt_hex") == salt.hex()


def test_parse_user_hashes_tomcat_sha256():
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    pw = _sha256_pw("hunter2")
    xml = (
        b'<?xml version="1.0"?>\n'
        b'<tomcat-users>'
        b'<user username="bob" password="' + pw.encode()
        + b'" roles="user"/>'
        b'</tomcat-users>'
    )
    out = parse_user_hashes_from_xml(xml)
    users = out.get("users") if isinstance(out, dict) else []
    assert len(users) == 1
    assert users[0]["username"] == "bob"


def test_parse_user_hashes_skips_users_without_username():
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    xml = (
        b'<?xml version="1.0"?>\n'
        b'<tomcat-users>'
        b'<user password="{SHA}xyz" roles="user"/>'   # no username
        b'<user username="bob" password="' + _sha_pw("x").encode()
        + b'" roles="user"/>'
        b'</tomcat-users>'
    )
    out = parse_user_hashes_from_xml(xml)
    users = out.get("users") if isinstance(out, dict) else []
    # Only "bob" should be picked up
    names = [u["username"] for u in users]
    assert names == ["bob"]


def test_parse_user_hashes_handles_invalid_xml():
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    out = parse_user_hashes_from_xml(b"<not valid xml")
    assert out.get("ok") is False
    assert "XML parse error" in out.get("error", "")


# Real-world SCC 2.19+ users.xml with all <user> elements on a single
# line (saved compact, attribute order is roles/groups/password/username).
# Captured from a live target — was missing 8 of 9 users due to the
# old per-line re.search() bug.
_SCC_REAL_USERS_XML = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<tomcat-users version="1.0" '
    b'xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd" '
    b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    b'xmlns="http://tomcat.apache.org/xml">'
    b'<role rolename="sccdisplay"/><role rolename="sccsupport"/>'
    b'<role rolename="admin"/><role rolename="sccadmin"/>'
    b'<role rolename="sccsubadmin"/><role rolename="sccmonitoring"/>'
    b'<group roles="" groupname="initial"/>'
    b'<user roles="admin" groups="" '
    b'password="A004DC3E8EB6EBB2315929D0F72AEA87686B44A9CA7EF38EEECC7EA39975F15F" '
    b'username="Administrator"/>'
    b'<user roles="sccsupport" groups="" '
    b'password="A0B939823E93066D336543F80047ACC8420956B52EFBF06064E8377DA662D818" '
    b'username="SCC_Support"/>'
    b'<user roles="sccdisplay" groups="" '
    b'password="A0B939823E93066D336543F80047ACC8420956B52EFBF06064E8377DA662D818" '
    b'username="SCC_Display"/>'
    b'<user roles="sccsubadmin" groups="" '
    b'password="A0B939823E93066D336543F80047ACC8420956B52EFBF06064E8377DA662D818" '
    b'username="SCC_SubAdmin"/>'
    b'<user roles="admin" groups="" '
    b'password="181229424893bb65d94a74c2132b8b9e5adfe851464fdb5cb9f49e8a8204be7b" '
    b'username="GJ"/>'
    b'<user roles="sccmonitoring" groups="" '
    b'password="A0B939823E93066D336543F80047ACC8420956B52EFBF06064E8377DA662D818" '
    b'username="SCC_Mon"/>'
    b'<user roles="sccmonitoring" groups="" '
    b'password="A0B939823E93066D336543F80047ACC8420956B52EFBF06064E8377DA662D818" '
    b'username="TestUser"/>'
    b'<user roles="admin" groups="" '
    b'password="A004DC3E8EB6EBB2315929D0F72AEA87686B44A9CA7EF38EEECC7EA39975F15F" '
    b'username="P4S"/>'
    b'</tomcat-users>'
)


def test_parse_user_hashes_real_world_compact_xml_extracts_all_users():
    """Live SCC 2.19+ XML stores every user on the same line.  Parser
    must extract all 9 users (Administrator, SCC_*, GJ, TestUser, P4S),
    not just the first one."""
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    out = parse_user_hashes_from_xml(_SCC_REAL_USERS_XML)
    users = out.get("users", []) if isinstance(out, dict) else []
    names = sorted(u["username"] for u in users)
    assert names == sorted([
        "Administrator", "SCC_Support", "SCC_Display", "SCC_SubAdmin",
        "GJ", "SCC_Mon", "TestUser", "P4S",
    ])
    assert len(users) == 8
    # Every user gets the raw-hex SHA-256 path (mode 1400)
    assert all(u["hashcat_mode"] == 1400 for u in users)
    assert all(len(u["hash_hex"]) == 64 for u in users)


def test_parse_user_hashes_attribute_order_independent():
    """SCC 2.19+ writes attrs in (roles, groups, password, username) order;
    older Tomcat builds use (username, password, roles).  Parser must
    handle either."""
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    xml = (
        b'<?xml version="1.0"?><tomcat-users>'
        # roles-first attribute order (SCC 2.19+ form)
        b'<user roles="admin" groups="" password="' + b'a' * 64
        + b'" username="alice"/>'
        b'</tomcat-users>'
    )
    out = parse_user_hashes_from_xml(xml)
    users = out.get("users", [])
    assert len(users) == 1
    assert users[0]["username"] == "alice"
    assert users[0]["roles"] == "admin"


# ===========================================================================
# 8. findstr post-processing — multi-<user> per line
# ===========================================================================
#
# The Windows users.xml extraction path runs `findstr` against the file to
# collapse it into matching lines, then rebuilds a clean XML byte string for
# parse_user_hashes_from_xml.  The rebuild logic lives inline inside the
# /api/scc/<host>/download_user_hashes handler so we exercise it via the
# same regex/iter logic with a tiny helper.

def _rebuild_xml_from_findstr_output(text: str) -> bytes:
    """Mirror of the inline rebuild in sapmap_gui — extracted so we can
    test the multi-element / attr-order behaviour directly."""
    import re
    user_re = re.compile(r"<user\b([^/>]*)/?\s*>", re.IGNORECASE)
    attr_re = re.compile(r"(\w+)\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
    parts = [b'<?xml version="1.0" encoding="utf-8"?>', b'<tomcat-users>']
    for m in user_re.finditer(text):
        attrs = {k.lower(): v for k, v in attr_re.findall(m.group(1))}
        uname = attrs.get("username", "")
        if not uname:
            continue
        pwd = attrs.get("password", "")
        roles = attrs.get("roles", "")
        parts.append(
            f'  <user username="{uname}" password="{pwd}" '
            f'roles="{roles}"/>'.encode())
    parts.append(b'</tomcat-users>')
    return b"\n".join(parts)


def test_findstr_rebuild_multi_user_single_line():
    """Findstr returns the entire users.xml content as one line — rebuild
    must extract every <user> element, not just the first."""
    one_line = _SCC_REAL_USERS_XML.decode("utf-8")
    raw = _rebuild_xml_from_findstr_output(one_line)
    # Parse the rebuilt XML and check we have all 8 users
    from sapmap_scc_keystore import parse_user_hashes_from_xml
    out = parse_user_hashes_from_xml(raw)
    users = out.get("users", [])
    assert len(users) == 8
    names = sorted(u["username"] for u in users)
    assert "Administrator" in names
    assert "GJ" in names
    assert "P4S" in names


def test_findstr_rebuild_attribute_order_independent():
    """Real findstr output puts attrs in the file's order — must handle
    roles/groups/password/username (SCC 2.19+ form)."""
    text = ('<user roles="admin" groups="" '
            'password="' + 'a' * 64 + '" username="alice"/>')
    raw = _rebuild_xml_from_findstr_output(text)
    assert b'username="alice"' in raw
    assert b'password="' + b'a' * 64 + b'"' in raw


def test_findstr_rebuild_skips_user_without_username():
    """An empty username in the source must produce zero <user> in the rebuild."""
    text = '<user roles="admin" password="abc"/>'
    raw = _rebuild_xml_from_findstr_output(text)
    # Should produce just the wrapper, no <user> entries
    assert b"<user " not in raw


# ===========================================================================
# 6. sapmap_scc_relay.probe_mapping — mocked TCP/HTTP
# ===========================================================================

def test_probe_mapping_http_reachable():
    """HTTP mapping with a 200/4xx/5xx response → reachable=True."""
    import sapmap_scc_relay as relay
    m = {"internal_host": "10.0.0.5", "internal_port": 8080,
         "protocol": "HTTP"}
    with patch.object(relay, "_http_head",
                      return_value=(True, 12.3, "HTTP/1.1 200 OK", "")):
        out = relay.probe_mapping(m, timeout=1.0)
    assert out["reachable"] is True
    assert out["probe_signature"].startswith("HTTP/")
    assert m["reachable"] is True   # mutates input in place


def test_probe_mapping_tcp_only_for_rfc():
    """RFC mapping → use plain TCP connect."""
    import sapmap_scc_relay as relay
    m = {"internal_host": "10.0.0.6", "internal_port": 3300,
         "protocol": "RFC"}
    with patch.object(relay, "_tcp_connect",
                      return_value=(True, 5.0, "")) as tcp_mock, \
         patch.object(relay, "_http_head") as http_mock:
        out = relay.probe_mapping(m, timeout=1.0)
    assert out["reachable"] is True
    assert out["probe_signature"] == "tcp-ok"
    tcp_mock.assert_called_once()
    http_mock.assert_not_called()


def test_probe_mapping_missing_endpoint():
    """Empty internal_host or internal_port = 0 → graceful error."""
    import sapmap_scc_relay as relay
    out = relay.probe_mapping({"internal_host": "", "internal_port": 8080,
                                "protocol": "HTTP"})
    assert out["reachable"] is False
    assert "missing" in out["probe_error"]

    out = relay.probe_mapping({"internal_host": "10.0.0.5",
                                "internal_port": 0,
                                "protocol": "HTTP"})
    assert out["reachable"] is False
    assert "missing" in out["probe_error"]


def test_probe_mapping_unknown_protocol_falls_back_to_tcp():
    """An unknown protocol must still produce a reachability bit."""
    import sapmap_scc_relay as relay
    m = {"internal_host": "10.0.0.7", "internal_port": 9000,
         "protocol": "WEIRD_PROTO"}
    with patch.object(relay, "_tcp_connect",
                      return_value=(True, 3.0, "")):
        out = relay.probe_mapping(m, timeout=1.0)
    assert out["reachable"] is True
    assert "WEIRD_PROTO" in out["probe_signature"]


def test_probe_all_yields_indexed_results():
    import sapmap_scc_relay as relay
    mappings = [
        {"internal_host": "h1", "internal_port": 80, "protocol": "HTTP"},
        {"internal_host": "h2", "internal_port": 81, "protocol": "HTTP"},
    ]
    with patch.object(relay, "_http_head",
                      return_value=(True, 1.0, "HTTP/1.1 200", "")):
        out = list(relay.probe_all(mappings, timeout=1.0))
    assert len(out) == 2
    assert out[0][0] == 0 and out[1][0] == 1
    assert out[0][2]["reachable"] is True


def test_probe_all_skips_non_dict_entries():
    """probe_all must skip garbage list entries gracefully."""
    import sapmap_scc_relay as relay
    out = list(relay.probe_all([None, "garbage", {"internal_host": "h",
                                                   "internal_port": 80,
                                                   "protocol": "HTTP"}]))
    # Only the dict entry should produce a result
    assert len(out) == 1
    assert out[0][0] == 2


# ===========================================================================
# 7. Windows multi-drive SCC discovery (sapmap_gui helpers)
# ===========================================================================

def test_enumerate_windows_drives_parses_fsutil_output():
    """fsutil's 'Drives: A:\\ C:\\ D:\\ P:\\' must produce the right list."""
    from sapmap_gui import _enumerate_windows_drives
    fake_gw_output = "Drives: A:\\ C:\\ D:\\ P:\\"
    out = _enumerate_windows_drives(lambda c, p: (fake_gw_output, True))
    assert "C:" in out and "D:" in out and "P:" in out
    # No mangling — drive letters stripped of backslashes, exact case
    assert all(d.endswith(":") and len(d) == 2 for d in out)


def test_enumerate_windows_drives_handles_string_return():
    """Tuples (out, ok) AND bare strings must both work — different
    callers in the codebase use different _gw shapes."""
    from sapmap_gui import _enumerate_windows_drives
    out = _enumerate_windows_drives(lambda c, p: "Drives: C:\\ D:\\")
    assert "C:" in out and "D:" in out


def test_enumerate_windows_drives_fallback_on_empty():
    """fsutil silently failing must not produce an empty list — the
    callers depend on at least C: being present."""
    from sapmap_gui import _enumerate_windows_drives
    out = _enumerate_windows_drives(lambda c, p: ("", True))
    assert out == ["C:"]


def test_enumerate_windows_drives_fallback_on_exception():
    """If the gw helper raises, we still return C: rather than crash."""
    from sapmap_gui import _enumerate_windows_drives
    def boom(c, p):
        raise RuntimeError("SAPXPG offline")
    out = _enumerate_windows_drives(boom)
    assert out == ["C:"]


def test_enumerate_windows_drives_dedups_and_keeps_c_first():
    """Even if fsutil reports drives without C:, C: still gets prepended."""
    from sapmap_gui import _enumerate_windows_drives
    out = _enumerate_windows_drives(lambda c, p: "Drives: D:\\ E:\\")
    assert out[0] == "C:"
    assert "D:" in out and "E:" in out


def test_expand_scc_roots_across_drives_cross_product():
    """Every drive × every template must appear in the output."""
    from sapmap_gui import (_expand_scc_roots_across_drives,
                             _WIN_SCC_ROOT_TEMPLATES)
    drives = ["C:", "P:"]
    out = _expand_scc_roots_across_drives(drives)
    assert len(out) == len(drives) * len(_WIN_SCC_ROOT_TEMPLATES)
    # Spot-checks: P:\SAP\scc20 must be there
    assert r"P:\SAP\scc20" in out
    assert r"C:\SAP\scc20" in out
    # Path separators are backslashes (Windows form)
    for r in out:
        assert "\\" in r and "/" not in r


def test_expand_scc_roots_includes_program_files_paths():
    """Both Program Files variants must be included for every drive."""
    from sapmap_gui import _expand_scc_roots_across_drives
    out = _expand_scc_roots_across_drives(["P:"])
    assert r"P:\Program Files\SAP\Cloud Connector" in out
    assert r"P:\Program Files\SAP\SAP Cloud Connector" in out


def test_expand_scc_roots_includes_usr_layout():
    """The Linux-style \\usr\\scc* layout (observed live on a P:\\ drive)
    must be probed for every drive."""
    from sapmap_gui import _expand_scc_roots_across_drives
    out = _expand_scc_roots_across_drives(["P:"])
    assert r"P:\usr\scc20" in out
    assert r"P:\usr\scc" in out
    assert r"P:\usr\scc21" in out
    assert r"P:\usr\scc22" in out
    assert r"P:\usr\scc19" in out
    # And the same for C:
    assert r"C:\usr\scc20" in _expand_scc_roots_across_drives(["C:"])


def test_expand_scc_roots_empty_drive_list():
    """No drives → empty roots list (don't fabricate)."""
    from sapmap_gui import _expand_scc_roots_across_drives
    assert _expand_scc_roots_across_drives([]) == []


# ===========================================================================
# Scanner: SCC port (8443) survives the WD-fingerprint loop
# ===========================================================================
# Regression: 8443 was being appended to ports_pass1 twice - once as
# 'scc_admin' (line ~722), once as 'wd_candidate' inside the
# WELL_KNOWN_WD_PORTS loop (line ~732).  Last-write-wins meant 8443
# ended up tagged as wd_candidate.  The WD fingerprint then ran
# against the SCC admin UI (which doesn't speak /sap/wdisp/admin),
# fingerprint failed with is_wd=False / is_sap_icm=False, and the
# port was DELETED from open_ports.  _maybe_build_scc_node then
# checked `SCC_DEFAULT_PORT not in open_ports` and bailed - the
# SCC node was never created.
#
# Fix: when the WD fingerprint fails on port == SCC_DEFAULT_PORT,
# re-tag the port as 'scc_admin' instead of deleting it, so the
# downstream SCC-specific fingerprint can run.


def _scanner_src():
    """Return the sapmap_scanner.py source text for grep-style assertions."""
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "modules" / "discovery" / "sapmap_scanner.py"
            ).read_text(encoding="utf-8")


def test_wd_fingerprint_loop_preserves_scc_port_on_exception_branch():
    """The fingerprint-exception branch must check
    p == SCC_DEFAULT_PORT and restore the scc_admin tag rather
    than deleting the port from open_ports.  Without this, an SCC
    on 8443 that times out the WD probe gets silently dropped
    before the SCC fingerprint ever runs."""
    src = _scanner_src()
    import re
    m = re.search(
        r"WD fingerprint error.*?continue",
        src, re.DOTALL)
    assert m, "WD fingerprint exception branch not found"
    body = m.group(0)
    assert "SCC_DEFAULT_PORT" in body, (
        "Exception branch must check p == SCC_DEFAULT_PORT so "
        "the SCC port isn't dropped when its WD probe errors out")
    assert '"scc_admin"' in body or "'scc_admin'" in body, (
        "Exception branch must restore the scc_admin service tag "
        "(not just skip the delete) so downstream _maybe_build_"
        "scc_node sees the port and can run the SCC fingerprint")


def test_wd_fingerprint_loop_preserves_scc_port_on_non_sap_branch():
    """The non-SAP-service branch must do the same: when the WD
    fingerprint says "not WD, not ICM" for 8443, the response
    probably came from an SCC (not nginx/apache).  Re-tag as
    scc_admin instead of deleting.

    Match anchor: the comment "Non-SAP service squatting the port"
    followed shortly by the SCC_DEFAULT_PORT guard + scc_admin
    re-tag.  The literal del-statement now lives inside an else
    branch so we can't anchor on it directly."""
    src = _scanner_src()
    import re
    m = re.search(
        r"Non-SAP service squatting the port.*?(?=\n    if|\n    result\[\"has_sap\"\])",
        src, re.DOTALL)
    assert m, "non-SAP-service branch not found"
    body = m.group(0)
    assert "SCC_DEFAULT_PORT" in body, (
        "non-SAP branch must check p == SCC_DEFAULT_PORT")
    assert '"scc_admin"' in body or "'scc_admin'" in body, (
        "non-SAP branch must restore scc_admin tag when the failed "
        "WD fingerprint is on the SCC port")
    # And the `del result[...][p]` must still exist (wrapped in an
    # else branch) so genuinely non-SAP ports (nginx etc.) still
    # get dropped.
    assert 'del result["open_ports"][p]' in body, (
        "non-SCC ports squatting WD candidate ports must still be "
        "dropped from open_ports (else branch missing)")


def test_scc_default_port_constant_matches_8443():
    """Lock the SCC_DEFAULT_PORT constant so a future refactor
    that changes it doesn't silently break the fingerprint
    fallback logic above (which hard-codes the comparison to
    SCC_DEFAULT_PORT but the regression-message references 8443
    explicitly for operator-readable context)."""
    import sys, pathlib
    discovery = (pathlib.Path(__file__).resolve().parent.parent
                 / "modules" / "discovery")
    sys.path.insert(0, str(discovery))
    try:
        from sapmap_scanner import SCC_DEFAULT_PORT
    finally:
        sys.path.remove(str(discovery))
    assert SCC_DEFAULT_PORT == 8443, (
        f"SCC_DEFAULT_PORT changed to {SCC_DEFAULT_PORT}; the "
        f"WD-fingerprint-loop fallback in sapmap_scanner.py "
        f"specifically guards p == SCC_DEFAULT_PORT - if the "
        f"constant moves, that guard must too")
