"""Tests for issue #141 — surface confirmed-open MS/ASCS ports in Open Ports.

The MS checks (check_ms_betrusted for 39NN; check_cve_2026_58240 for 36NN/39NN)
used to store a discovered-open message-server port only in node-level scalars
(node.ms_port / node.cve_2026_58240_ms_port), never on an instance's ports map —
so it never appeared in the node's "Open Ports". Now a CONFIRMED-open MS port (a
genuine MS protocol reply incl. ACL-denied `login_denied`, or a TLS handshake) is
recorded on its ASCS instance via `_record_instance_port`, mirroring the existing
`check_ms_info_disclosure` (msghttp) pattern — a bare TCP-accept with no MS frame
is NOT recorded.

Behaviour tests monkeypatch the lazily-imported wire functions in their SOURCE
modules (sap_cve_2026_58240.check_ascs_gw_registration,
sap_ms_betrusted.sapmap_check_ms / probe_ms_tls_required). Pure-helper tests call
the helpers directly.
"""
from __future__ import annotations

import inspect

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_scanner as S
from sapmap_models import SAPNode, InstanceInfo


# ===========================================================================
# _ms_port_label
# ===========================================================================

@pytest.mark.parametrize("port,expected", [
    (3600, ("00", "sapms")),
    (3601, ("01", "sapms")),
    (3642, ("42", "sapms")),
    (3900, ("00", "ms_internal")),
    (3901, ("01", "ms_internal")),
    (3200, None), (3300, None), (8000, None), (44300, None),
])
def test_ms_port_label(port, expected):
    assert S._ms_port_label(port) == expected


# ===========================================================================
# _record_instance_port
# ===========================================================================

def _node(ports=None, inst="00", ip="10.0.0.1"):
    n = SAPNode(sid="T", ip=ip)
    n.instances = [InstanceInfo(instance_nr=inst, ip=ip, ports=dict(ports or {}))]
    return n


def test_record_creates_ascs_instance_when_absent():
    """The MS/ASCS instance (e.g. 01) usually differs from the app-server
    instance (00) — it must be created, not merged into inst 00."""
    n = _node({3200: "dispatcher"}, inst="00")
    S._record_instance_port(n, "01", 3901, "ms_internal")
    assert [i.instance_nr for i in n.instances] == ["00", "01"]
    assert n.instances[1].ports == {3901: "ms_internal"}
    assert n.instances[0].ports == {3200: "dispatcher"}  # inst 00 untouched


def test_record_merges_into_existing_instance():
    n = _node({3301: "gateway"}, inst="01")
    S._record_instance_port(n, "01", 3901, "ms_internal")
    assert n.instances[0].ports == {3301: "gateway", 3901: "ms_internal"}


def test_record_setdefault_does_not_clobber():
    n = _node({3200: "dispatcher"}, inst="00")
    S._record_instance_port(n, "00", 3200, "SHOULD_NOT_WIN")
    assert n.instances[0].ports[3200] == "dispatcher"


def test_record_non_fatal_on_bad_port():
    n = _node({}, inst="00")
    S._record_instance_port(n, "00", "notaport", "x")  # must not raise
    assert n.instances[0].ports == {}


# ===========================================================================
# check_cve_2026_58240 — records confirmed-open 36NN/39NN
# ===========================================================================

def _cve_mocks(monkeypatch, verdicts, tls_ports=()):
    import sap_cve_2026_58240 as CVE
    import sap_ms_betrusted as BT
    monkeypatch.setattr(CVE, "check_ascs_gw_registration",
                        lambda host, port, timeout=6.0:
                        {"verdict": verdicts.get(port, "unreachable")})
    monkeypatch.setattr(BT, "probe_ms_tls_required",
                        lambda host, p, timeout=4.0:
                        "tls_required" if p in tls_ports else "plaintext")


def _abap_node(sid="SBD"):
    n = SAPNode(sid=sid, ip="10.0.0.14")
    n.kernel = "916"  # 9.x → TLS re-probe path enabled
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.14",
                                ports={3200: "dispatcher", 3300: "gateway"})]
    return n


def test_cve_records_login_denied_and_tls_ports(monkeypatch):
    """The issue's exact case: 3601 ACL-denied (login_denied) + 3901 speaking
    TLS → both recorded on the ASCS instance (01)."""
    _cve_mocks(monkeypatch,
               verdicts={3601: "login_denied", 3901: "no_ms_reply"},
               tls_ports={3901})
    n = _abap_node()
    S.check_cve_2026_58240(n, timeout=1)
    ascs = next((i for i in n.instances if i.instance_nr == "01"), None)
    assert ascs is not None, "ASCS instance 01 must be created"
    assert ascs.ports.get(3601) == "sapms"
    assert ascs.ports.get(3901) == "ms_internal"
    # inst 00 untouched
    assert n.instances[0].ports == {3200: "dispatcher", 3300: "gateway"}


def test_cve_does_not_record_unreachable_or_bare_tcp(monkeypatch):
    """no_ms_reply (bare TCP) and unreachable must NOT be recorded."""
    _cve_mocks(monkeypatch,
               verdicts={3601: "no_ms_reply", 3901: "unreachable"},
               tls_ports=())  # no TLS reclassification
    n = _abap_node("X")
    S.check_cve_2026_58240(n, timeout=1)
    all_ports = {p for i in n.instances for p in i.ports}
    assert 3601 not in all_ports and 3901 not in all_ports


def test_cve_records_opcode_recognised(monkeypatch):
    _cve_mocks(monkeypatch, verdicts={3901: "opcode_recognised"})
    n = _abap_node("V")
    S.check_cve_2026_58240(n, timeout=1)
    ascs = next((i for i in n.instances if i.instance_nr == "01"), None)
    assert ascs is not None and ascs.ports.get(3901) == "ms_internal"


def test_cve_records_opcode_out_of_scope_on_pre_9x_kernel(monkeypatch):
    """REGRESSION (adversarial review): on a pre-9.x kernel an
    opcode_recognised verdict is downgraded to opcode_out_of_scope — the MS
    login still succeeded, so the port is a confirmed listener and must
    still be recorded (it skips the opcode early-return branch)."""
    _cve_mocks(monkeypatch, verdicts={3901: "opcode_recognised"})
    n = _abap_node("OOS")
    n.kernel = "793"  # pre-9.x → opcode_recognised downgraded out of scope
    S.check_cve_2026_58240(n, timeout=1)
    assert n.cve_2026_58240_evidence == "opcode_out_of_scope"
    ascs = next((i for i in n.instances if i.instance_nr == "01"), None)
    assert ascs is not None and ascs.ports.get(3901) == "ms_internal", (
        "a downgraded-but-open MS port must still be recorded")


# ===========================================================================
# check_ms_betrusted — records internal 39NN on a strong signal
# ===========================================================================

def _bt_mock(monkeypatch, result_by_inst):
    import sap_ms_betrusted as BT
    def fake(host, inst_nr, timeout):
        return result_by_inst.get(inst_nr, {
            "port": 3900 + inst_nr, "accessible": False, "vulnerable": False,
            "acl_protected": False, "secure_comms_required": False})
    monkeypatch.setattr(BT, "sapmap_check_ms", fake)


def test_betrusted_records_internal_port_on_strong_signal(monkeypatch):
    _bt_mock(monkeypatch, {1: {
        "port": 3901, "accessible": True, "vulnerable": False,
        "acl_protected": False, "secure_comms_required": True}})
    n = SAPNode(sid="B", ip="10.0.0.14")
    n.instances = [InstanceInfo(instance_nr="01", ip="10.0.0.14",
                                ports={3301: "gateway"})]
    S.check_ms_betrusted(n, timeout=1)
    all_ports = {p: lbl for i in n.instances for p, lbl in i.ports.items()}
    assert all_ports.get(3901) == "ms_internal"


def test_betrusted_records_acl_protected(monkeypatch):
    _bt_mock(monkeypatch, {1: {
        "port": 3901, "accessible": True, "vulnerable": False,
        "acl_protected": True, "secure_comms_required": False}})
    n = SAPNode(sid="B3", ip="10.0.0.14")
    n.instances = [InstanceInfo(instance_nr="01", ip="10.0.0.14", ports={})]
    S.check_ms_betrusted(n, timeout=1)
    all_ports = {p: lbl for i in n.instances for p, lbl in i.ports.items()}
    assert all_ports.get(3901) == "ms_internal"


def test_betrusted_does_not_record_bare_accessible(monkeypatch):
    """TCP accepted but no MS reply / TLS → do NOT record (bare accessible)."""
    _bt_mock(monkeypatch, {1: {
        "port": 3901, "accessible": True, "vulnerable": False,
        "acl_protected": False, "secure_comms_required": False}})
    n = SAPNode(sid="B2", ip="10.0.0.14")
    n.instances = [InstanceInfo(instance_nr="01", ip="10.0.0.14",
                                ports={3301: "gateway"})]
    S.check_ms_betrusted(n, timeout=1)
    all_ports = {p for i in n.instances for p in i.ports}
    assert 3901 not in all_ports


# ===========================================================================
# check_ms_info_disclosure still routes through the shared helper (refactor)
# ===========================================================================

def test_ms_info_disclosure_uses_shared_helper():
    src = inspect.getsource(S.check_ms_info_disclosure)
    assert '_record_instance_port(node, inst_nr, port, "msghttp"' in src
    # the old inline find-or-create block is gone
    assert 'matched.ports[int(port)] = "msghttp"' not in src
