#!/usr/bin/env python3
"""Tests for the `/sap/public/info` pre-auth fingerprint integration.

Covers:
  * query_public_info() parser — successful SOAP envelope, namespace
    variations, 404 / non-200 rejection, missing RFCSI_EXPORT rejection.
  * enrich_system_info() integration — public/info fills empty RFCSI
    fields, skipped on Java-only stacks, uses SAPControl ICM ports when
    present, falls back to 80NN / 5XX80 defaults otherwise.
"""

from __future__ import annotations

from unittest.mock import patch


# ---------------------------------------------------------------------------
# Sample responses
# ---------------------------------------------------------------------------

_SOAP_OK = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/xml; charset=iso-8859-1\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b'<?xml version="1.0" encoding="iso-8859-1"?>'
    b'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
    b"<SOAP-ENV:Body>"
    b'<rfc:RFC_SI_GET_SYSTEM_INFO.Response xmlns:rfc="urn:sap-com:document:sap:rfc:functions">'
    b"<RFCSI_EXPORT>"
    b"<RFCPROTO>011</RFCPROTO>"
    b"<RFCDEST>S4HCLNT100</RFCDEST>"
    b"<RFCHOST>s4hanadev</RFCHOST>"
    b"<RFCSYSID>S4H</RFCSYSID>"
    b"<RFCDATABS>S4H</RFCDATABS>"
    b"<RFCDBHOST>s4hanadev</RFCDBHOST>"
    b"<RFCDBSYS>HDB</RFCDBSYS>"
    b"<RFCSAPRL>758</RFCSAPRL>"
    b"<RFCOPSYS>Linux</RFCOPSYS>"
    b"<RFCTZONE>0</RFCTZONE>"
    b"<RFCIPADDR>192.168.2.209</RFCIPADDR>"
    b"<RFCKERNRL>789</RFCKERNRL>"
    b"<RFCHOST2>s4hanadev</RFCHOST2>"
    b"<RFCIPV6ADDR>192.168.2.209</RFCIPV6ADDR>"
    b"</RFCSI_EXPORT>"
    b"</rfc:RFC_SI_GET_SYSTEM_INFO.Response>"
    b"</SOAP-ENV:Body></SOAP-ENV:Envelope>"
)

_SOAP_NO_NS = (
    b"HTTP/1.0 200 OK\r\n"
    b"Content-Type: text/xml\r\n\r\n"
    b"<Envelope><Body><RFCSI_EXPORT>"
    b"<RFCSYSID>NW7</RFCSYSID>"
    b"<RFCHOST>nw7host</RFCHOST>"
    b"<RFCOPSYS>Windows NT</RFCOPSYS>"
    b"<RFCDBSYS>MSS</RFCDBSYS>"
    b"<RFCSAPRL>755</RFCSAPRL>"
    b"<RFCKERNRL>781</RFCKERNRL>"
    b"</RFCSI_EXPORT></Body></Envelope>"
)

_HTTP_404 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
_HTTP_401 = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b"WWW-Authenticate: Basic realm=\"SAP\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)
_HTTP_200_NON_SAP = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b"<html><body>not a SAP system</body></html>"
)


# ---------------------------------------------------------------------------
# Fake socket — feeds canned bytes into recv()
# ---------------------------------------------------------------------------

class _FakeSock:
    def __init__(self, payload: bytes):
        self._buf = payload

    def settimeout(self, *a, **k):
        pass

    def connect(self, *a, **k):
        pass

    def sendall(self, *a, **k):
        pass

    def recv(self, n):
        if not self._buf:
            return b""
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def close(self):
        pass


def _patch_socket(monkeypatch, payload):
    import sapmap_scanner

    def _fake_socket(*a, **k):
        return _FakeSock(payload)

    monkeypatch.setattr(sapmap_scanner.socket, "socket", _fake_socket)


# ---------------------------------------------------------------------------
# query_public_info — parser
# ---------------------------------------------------------------------------

def test_public_info_parses_full_soap_envelope(monkeypatch):
    import sapmap_scanner
    _patch_socket(monkeypatch, _SOAP_OK)
    out = sapmap_scanner.query_public_info("s4hanadev", 8000)
    assert out["sid"] == "S4H"
    assert out["hostname"] == "s4hanadev"   # RFCHOST2 wins
    assert out["os_type"] == "Linux"
    assert out["db_type"] == "HDB"
    assert out["kernel"] == "789"
    assert out["sap_release"] == "758"
    assert out["ip"] == "192.168.2.209"     # RFCIPV6ADDR
    assert out["db_host"] == "s4hanadev"
    assert out["timezone"] == "0"


def test_public_info_handles_unprefixed_xml(monkeypatch):
    """Some kernels emit RFCSI fields without a namespace prefix."""
    import sapmap_scanner
    _patch_socket(monkeypatch, _SOAP_NO_NS)
    out = sapmap_scanner.query_public_info("nw7host", 8000)
    assert out["sid"] == "NW7"
    assert out["os_type"] == "Windows NT"
    assert out["db_type"] == "MSS"
    assert out["kernel"] == "781"
    # Fields not present in response must not appear in the dict
    assert "db_host" not in out
    assert "timezone" not in out


def test_public_info_rejects_404(monkeypatch):
    import sapmap_scanner
    _patch_socket(monkeypatch, _HTTP_404)
    assert sapmap_scanner.query_public_info("java.example", 50000) == {}


def test_public_info_rejects_401(monkeypatch):
    """Old kernels with auth-gated /sap/public/* — still no parse."""
    import sapmap_scanner
    _patch_socket(monkeypatch, _HTTP_401)
    assert sapmap_scanner.query_public_info("oldnw.example", 8000) == {}


def test_public_info_rejects_non_sap_200(monkeypatch):
    """HTTP 200 but body has no RFCSI_EXPORT — must reject."""
    import sapmap_scanner
    _patch_socket(monkeypatch, _HTTP_200_NON_SAP)
    assert sapmap_scanner.query_public_info("nginx.example", 8000) == {}


def test_public_info_returns_empty_on_connection_failure(monkeypatch):
    import sapmap_scanner

    def _raise(*a, **k):
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(sapmap_scanner.socket, "socket", _raise)
    assert sapmap_scanner.query_public_info("dead.example", 8000) == {}


# ---------------------------------------------------------------------------
# enrich_system_info — integration
# ---------------------------------------------------------------------------

def _no_op_diag_ms_os(monkeypatch):
    """Stub out the DIAG/MS-HTTP/OS fallbacks so they don't interfere."""
    import sapmap_scanner
    monkeypatch.setattr(sapmap_scanner, "_query_diag_dispatcher_info",
                         lambda *a, **k: ("", "", ""))
    monkeypatch.setattr(sapmap_scanner, "_query_ms_http_info",
                         lambda *a, **k: ("", "", ""))
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_os",
                         lambda *a, **k: "")


def test_enrich_uses_public_info_to_fill_empty_fields(monkeypatch):
    """RFC + SAPControl yield no kernel/OS; public/info fills them in."""
    import sapmap_scanner

    monkeypatch.setattr(sapmap_scanner, "probe_sap_system",
                         lambda *a, **k: {"status": "rfc_success",
                                            "RFCSYSID": "S4H",
                                            "RFCHOST2": "s4hanadev"})
    # SAPControl reports SID + ABAP stack + ICM HTTP 8000, but no DB / kernel
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid",
                         lambda *a, **k: ("S4H", False, True, "", 8000, 0))
    _no_op_diag_ms_os(monkeypatch)

    calls = []
    def fake_pi(host, port, timeout=5, saprouter=""):
        calls.append((host, port))
        return {"sid": "S4H", "hostname": "s4hanadev",
                "os_type": "Linux", "db_type": "HDB",
                "kernel": "789", "sap_release": "758",
                "ip": "192.168.2.209", "db_host": "s4hanadev",
                "timezone": "0"}

    monkeypatch.setattr(sapmap_scanner, "query_public_info", fake_pi)

    info = sapmap_scanner.enrich_system_info("s4hanadev", 3300,
                                              instance_nrs=[0],
                                              sid_hint="S4H")
    # public/info was queried on the SAPControl-discovered HTTP port
    assert ("s4hanadev", 8000) in calls
    assert info["os_type"] == "Linux"
    assert info["db_type"] == "HDB"
    assert info["kernel"] == "789"
    assert info["sap_release"] == "758"
    assert info.get("db_host") == "s4hanadev"
    assert info.get("timezone") == "0"
    assert info.get("_is_abap") is True
    assert info.get("_public_info_source") == "s4hanadev:8000"


def test_enrich_skips_public_info_on_java_only_stack(monkeypatch):
    import sapmap_scanner

    monkeypatch.setattr(sapmap_scanner, "probe_sap_system",
                         lambda *a, **k: {"status": "rfc_success",
                                            "RFCSYSID": "SJ1"})
    # SAPControl pins Java-only
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid",
                         lambda *a, **k: ("SJ1", True, False, "HDB",
                                            50000, 50001))
    _no_op_diag_ms_os(monkeypatch)

    calls = []
    def fake_pi(*a, **k):
        calls.append(a)
        return {"sid": "X"}

    monkeypatch.setattr(sapmap_scanner, "query_public_info", fake_pi)

    sapmap_scanner.enrich_system_info("javahost", 3300,
                                       instance_nrs=[0],
                                       sid_hint="SJ1")
    # Must NOT have queried public/info on a Java-only stack
    assert calls == []


def test_enrich_falls_back_to_default_icm_ports_when_sapcontrol_silent(
        monkeypatch):
    """SAPControl never returned an ICM port — public/info must still
    try the standard ABAP defaults 80NN and 5XX80."""
    import sapmap_scanner

    monkeypatch.setattr(sapmap_scanner, "probe_sap_system",
                         lambda *a, **k: {"status": "rfc_success",
                                            "RFCSYSID": "S4H"})
    # SAPControl returns nothing (no stack flags, no ICM ports)
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid",
                         lambda *a, **k: ("", False, False, "", 0, 0))
    _no_op_diag_ms_os(monkeypatch)

    tried = []
    def fake_pi(host, port, timeout=5, saprouter=""):
        tried.append(port)
        # First port (8000) succeeds — second default (50080) should
        # NOT be tried because the loop breaks on first hit.
        if port == 8000:
            return {"sid": "S4H", "os_type": "Linux"}
        return {}

    monkeypatch.setattr(sapmap_scanner, "query_public_info", fake_pi)

    info = sapmap_scanner.enrich_system_info("host.example", 3300,
                                              instance_nrs=[0],
                                              sid_hint="S4H")
    assert 8000 in tried              # tried default ICM port
    assert 50080 not in tried         # short-circuited on success
    assert info["os_type"] == "Linux"
    assert info.get("_is_abap") is True


def test_enrich_does_not_overwrite_rfc_fields(monkeypatch):
    """RFC_SYSTEM_INFO data wins over /sap/public/info — public/info is
    only used to FILL empty fields."""
    import sapmap_scanner

    monkeypatch.setattr(sapmap_scanner, "probe_sap_system",
                         lambda *a, **k: {"status": "rfc_success",
                                            "RFCSYSID": "S4H",
                                            "RFCOPSYS": "Linux",
                                            "RFCDBSYS": "HDB",
                                            "RFCKERNRL": "789",
                                            "RFCSAPRL": "758"})
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid",
                         lambda *a, **k: ("S4H", False, True, "HDB",
                                            8000, 0))
    _no_op_diag_ms_os(monkeypatch)

    # public/info returns DIFFERENT values — they must be ignored
    monkeypatch.setattr(sapmap_scanner, "query_public_info",
                         lambda *a, **k: {"sid": "S4H",
                                            "os_type": "Windows NT",
                                            "db_type": "MSS",
                                            "kernel": "999",
                                            "sap_release": "999"})

    info = sapmap_scanner.enrich_system_info("s4hanadev", 3300,
                                              instance_nrs=[0],
                                              sid_hint="S4H")
    assert info["os_type"] == "Linux"
    assert info["db_type"] == "HDB"
    assert info["kernel"] == "789"
    assert info["sap_release"] == "758"
