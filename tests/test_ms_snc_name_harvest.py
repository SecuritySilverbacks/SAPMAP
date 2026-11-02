"""Unauthenticated SNC-name harvest from the Message Server text/logon list.

The MS /msgserver/text/logon access-point list names the SNC partner
identity for every SNC-protected service (RFCS on 48NN, DIAGS on 32NN).
These tests cover the pure parser, the preference logic, the MS-port
derivation/gating, and the ``harvest_ms_snc_name`` side effects
(snc_partnername threading + finding).  Identifiers are synthetic.
"""
import sapmap_scanner
from sapmap_models import SAPNode, InstanceInfo


# A message server's unauthenticated GET /msgserver/text/logon response —
# HTTP headers + the tab-separated access-point list.  The SNC-protected
# services (DIAGS / RFCS) carry the server's SNC name in the 4th column.
MS_LOGON = (
    b"HTTP/1.1 200 OK\r\n"
    b"content-type: text/plain; charset=utf-8\r\n"
    b"server: SAP Message Server, release 916 (PRD)\r\n"
    b"\r\n"
    b"version 1.0\n"
    b"msrv01_PRD_00\n"
    b"DIAG\tmsrv01.corp.example\t3200\tLB=10\n"
    b"DIAGS\tmsrv01.corp.example\t3200\tp/cstb:prd.corp.example\n"
    b"RFC\tmsrv01.corp.example\t3300\t\n"
    b"RFCS\tmsrv01.corp.example\t4800\tp/cstb:prd.corp.example\n"
    b"HTTPS\tmsrv01.corp.example\t44300\t\n"
)
SNC_NAME = "p/cstb:prd.corp.example"

# A system whose SNC name is a CommonCryptoLib X.509 DN (spaces + commas).
X509_LOGON = (
    b"version 1.0\n"
    b"app01_PRD_00\n"
    b"RFCS\tapp01.corp.example\t4800\tp:CN=PRD, O=Example Corp, C=NL\n"
)

# No SNC-protected service advertised (plain RFC/DIAG only).
PLAIN_LOGON = (
    b"version 1.0\n"
    b"app02_ABC_00\n"
    b"DIAG\tapp02.corp.example\t3200\tLB=10\n"
    b"RFC\tapp02.corp.example\t3300\t\n"
)


def test_parse_extracts_snc_names_and_skips_plain_rows():
    aps = sapmap_scanner._parse_ms_logon_access_points(MS_LOGON)
    by_svc = {a["service"]: a for a in aps}
    # SNC-protected services carry the name...
    assert by_svc["RFCS"]["snc_name"] == SNC_NAME
    assert by_svc["RFCS"]["port"] == 4800
    assert by_svc["DIAGS"]["snc_name"] == SNC_NAME
    # ...plain services and LB hints do not.
    assert by_svc["RFC"]["snc_name"] == ""
    assert by_svc["DIAG"]["snc_name"] == ""   # "LB=10" is not an SNC name
    assert by_svc["HTTPS"]["snc_name"] == ""


def test_parse_preserves_x509_dn_with_spaces():
    aps = sapmap_scanner._parse_ms_logon_access_points(X509_LOGON)
    assert aps[0]["snc_name"] == "p:CN=PRD, O=Example Corp, C=NL"


def test_parse_handles_empty_and_garbage():
    assert sapmap_scanner._parse_ms_logon_access_points(b"") == []
    assert sapmap_scanner._parse_ms_logon_access_points(
        b"no tabs here\njust prose\n") == []


def test_pick_prefers_rfcs_over_diags():
    aps = sapmap_scanner._parse_ms_logon_access_points(MS_LOGON)
    name, port, svc = sapmap_scanner._pick_snc_name(aps)
    assert (name, port, svc) == (SNC_NAME, 4800, "RFCS")


def test_ms_http_candidates_derives_port_from_ascs_ms_ports():
    # ABAP app server on instance 00, message server on the ASCS instance 01
    # (MS internal 3601 / external 3901) — the MS HTTP port is 8101, derived
    # from the ASCS number, not 8100 from the app instance.
    node = SAPNode(sid="PRD", ip="10.0.0.14", instances=[
        InstanceInfo(instance_nr="00", ip="10.0.0.14",
                     ports={3200: "dispatcher", 3300: "gateway"}),
        InstanceInfo(instance_nr="01", ip="10.0.0.14",
                     ports={3601: "ms", 3901: "ms"}),
    ])
    ports = {p for p, _ in sapmap_scanner._ms_http_candidates(node)}
    assert 8101 in ports          # derived from 3601/3901 and from inst 01
    assert 8100 in ports          # app instance 00 still tried as a fallback


def test_has_ms_port_detects_ms_evidence():
    ms = SAPNode(sid="PRD", ip="10.0.0.14", instances=[
        InstanceInfo(instance_nr="01", ip="10.0.0.14", ports={3901: "ms"}),
    ])
    no_ms = SAPNode(sid="APP", ip="10.0.0.15", instances=[
        InstanceInfo(instance_nr="00", ip="10.0.0.15",
                     ports={3200: "dispatcher", 3300: "gateway"}),
    ])
    assert sapmap_scanner._has_ms_port(ms) is True
    assert sapmap_scanner._has_ms_port(no_ms) is False


def test_harvest_sets_partnername_and_emits_finding(monkeypatch):
    monkeypatch.setattr(sapmap_scanner, "_ms_http_get",
                        lambda *a, **k: MS_LOGON)
    node = SAPNode(sid="PRD", ip="10.0.0.14")
    out = sapmap_scanner.harvest_ms_snc_name(node, [(8100, 0)])

    assert out["found"] is True
    assert out["snc_name"] == SNC_NAME
    assert out["service"] == "RFCS"
    assert node.snc_partnername == SNC_NAME

    names = [getattr(f, "name", "") for f in node.findings]
    assert "SNC Partner Name Disclosure (MS text/logon)" in names


def test_harvest_does_not_overwrite_operator_value(monkeypatch):
    monkeypatch.setattr(sapmap_scanner, "_ms_http_get",
                        lambda *a, **k: MS_LOGON)
    node = SAPNode(sid="PRD", ip="10.0.0.14")
    node.snc_partnername = "p:CN=OPERATOR-SET"
    out = sapmap_scanner.harvest_ms_snc_name(node, [(8100, 0)])

    # Operator value kept, but the disclosure is still reported.
    assert node.snc_partnername == "p:CN=OPERATOR-SET"
    assert out["found"] is True


def test_harvest_noop_when_no_snc_service(monkeypatch):
    monkeypatch.setattr(sapmap_scanner, "_ms_http_get",
                        lambda *a, **k: PLAIN_LOGON)
    node = SAPNode(sid="ABC", ip="10.0.0.14")
    out = sapmap_scanner.harvest_ms_snc_name(node, [(8100, 0)])

    assert out["found"] is False
    assert node.snc_partnername == ""
    assert node.findings == []


def test_harvest_finding_not_duplicated_on_rescan(monkeypatch):
    monkeypatch.setattr(sapmap_scanner, "_ms_http_get",
                        lambda *a, **k: MS_LOGON)
    node = SAPNode(sid="PRD", ip="10.0.0.14")
    sapmap_scanner.harvest_ms_snc_name(node, [(8100, 0)])
    sapmap_scanner.harvest_ms_snc_name(node, [(8100, 0)])
    dupes = [f for f in node.findings
             if getattr(f, "name", "") ==
             "SNC Partner Name Disclosure (MS text/logon)"]
    assert len(dupes) == 1
