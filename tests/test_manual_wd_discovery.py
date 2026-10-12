"""Tests for issue #89 — manually-added Web Dispatcher discovery.

Three defects in the post-add enrichment (`enrich_system_info`, shared by
manual-add, the re-run button, and the auto scan):

  A. standard web ports 80/443 were never probed — now probed when the
     caller passes `include_web_ports=True` (manual-add / re-run only).
  B. instance 00 was injected unconditionally, cross-contaminating a node
     added at another instance with a co-located inst-00 system — now 00 is
     only a last resort when no instance is otherwise known.
  C. an HTTP 4xx/5xx/200-no-rfcsi response was discarded like a connection
     failure — now the port is recorded in `info["alive_http_ports"]` and
     the manual-add/re-run paths label it icm_http/icm_https on the node via
     `_apply_alive_http_ports`.

Two layers (mirroring the repo's conventions):
  * behaviour tests for `enrich_system_info` — monkeypatch the scanner's
    network helpers exactly as tests/test_public_info.py does.
  * pure-helper tests for `_apply_alive_http_ports` — direct calls on
    hand-built SAPNode/InstanceInfo, like tests/test_wd_set_type_rediscover.py.
"""
from __future__ import annotations

import inspect
import re

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_scanner
import sapmap_gui
from sapmap_models import SAPNode, InstanceInfo


# ===========================================================================
# Hermetic stubs (copied from tests/test_public_info.py so this file stands
# alone) — no real network I/O reaches a gateway/ICM/MS/OS probe.
# ===========================================================================

def _no_op_diag_ms_os(monkeypatch):
    import sap_rfc_sysinfo_probe
    monkeypatch.setattr(sap_rfc_sysinfo_probe, "probe_rfcsi",
                        lambda *a, **k: {"error": "disabled in tests"})
    monkeypatch.setattr(sapmap_scanner, "_query_diag_dispatcher_info",
                        lambda *a, **k: ("", "", ""))
    monkeypatch.setattr(sapmap_scanner, "_query_ms_http_info",
                        lambda *a, **k: ("", "", ""))
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_os",
                        lambda *a, **k: "")
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_process_names",
                        lambda *a, **k: None)


def _sapcontrol_silent(monkeypatch):
    """probe_sap_system 'succeeds' minimally; SAPControl returns no ICM
    ports/flags → enrich falls through to the default-port /sap/public/info
    probe loop (the code path all three #89 points live in)."""
    monkeypatch.setattr(sapmap_scanner, "probe_sap_system",
                        lambda *a, **k: {"status": "rfc_success",
                                         "RFCSYSID": "WDX"})
    monkeypatch.setattr(sapmap_scanner, "_query_sapcontrol_sid",
                        lambda *a, **k: ("", False, False, "", 0, 0))
    _no_op_diag_ms_os(monkeypatch)


def _collect_pi(monkeypatch, status_by_port=None, success_ports=()):
    """Install a fake query_public_info that records every probed port into
    the returned `tried` list.  Returns {} for all ports unless a port is in
    `success_ports`; sets `_last_status` from `status_by_port` (default
    'connect_failed:X' so nothing is recorded and the loop never breaks)."""
    tried = []
    status_by_port = status_by_port or {}

    def fake_pi(host, port, timeout=5, saprouter="", use_https=False):
        tried.append(port)
        fake_pi._last_status = status_by_port.get(port, "connect_failed:Stub")
        if port in success_ports:
            fake_pi._last_status = "ok"
            return {"sid": "WDX", "os_type": "Linux"}
        return {}

    monkeypatch.setattr(sapmap_scanner, "query_public_info", fake_pi)
    return tried


# ===========================================================================
# B — instance-00 injection
# ===========================================================================

def test_b_explicit_instance_does_not_probe_instance_00(monkeypatch):
    """Operator added inst 90 → probe 8090/44390, NOT the inst-00 defaults
    8000/44300 (the source of the issue's SID=NOT-SID contamination)."""
    _sapcontrol_silent(monkeypatch)
    tried = _collect_pi(monkeypatch)
    sapmap_scanner.enrich_system_info("host.example", 3390,
                                      instance_nrs=["90"], sid_hint="WDX")
    assert 8090 in tried and 44390 in tried
    assert 8000 not in tried
    assert 44300 not in tried


def test_b_gateway_instance_does_not_add_instance_00(monkeypatch):
    """Auto-scan path (no explicit instance) with gateway 3342 → inst 42 is
    probed, inst 00 is NOT force-added."""
    _sapcontrol_silent(monkeypatch)
    tried = _collect_pi(monkeypatch)
    sapmap_scanner.enrich_system_info("host.example", 3342, sid_hint="WDX")
    assert 8042 in tried
    assert 8000 not in tried


def test_b_instance_00_still_last_resort_when_nothing_known(monkeypatch):
    """No explicit instance and a non-gateway gw_port → inst 00 remains the
    sane last-resort guess."""
    _sapcontrol_silent(monkeypatch)
    tried = _collect_pi(monkeypatch)
    sapmap_scanner.enrich_system_info("host.example", 9999, sid_hint="WDX")
    assert 8000 in tried and 44300 in tried


# ===========================================================================
# A — standard web ports 80/443
# ===========================================================================

def test_a_web_ports_probed_when_flag_set(monkeypatch):
    _sapcontrol_silent(monkeypatch)
    tried = _collect_pi(monkeypatch)
    sapmap_scanner.enrich_system_info("host.example", 3390,
                                      instance_nrs=["90"], sid_hint="WDX",
                                      include_web_ports=True)
    assert 80 in tried
    assert 443 in tried


def test_a_web_ports_absent_by_default(monkeypatch):
    """Auto-scan (flag unset) must not pay the extra 80/443 probes — it
    already covers them via WELL_KNOWN_WD_PORTS."""
    _sapcontrol_silent(monkeypatch)
    tried = _collect_pi(monkeypatch)
    sapmap_scanner.enrich_system_info("host.example", 3390,
                                      instance_nrs=["90"], sid_hint="WDX")
    assert 80 not in tried
    assert 443 not in tried


# ===========================================================================
# C (report) — alive_http_ports
# ===========================================================================

def test_c_http_error_port_recorded_as_alive(monkeypatch):
    """A 4xx/5xx (HTTP response received) is recorded; a connection failure
    is NOT."""
    _sapcontrol_silent(monkeypatch)
    # 8090 → 503 (alive), 44390 → connect refused (not alive)
    _collect_pi(monkeypatch, status_by_port={8090: "http_503",
                                             44390: "connect_failed:Refused"})
    info = sapmap_scanner.enrich_system_info(
        "host.example", 3390, instance_nrs=["90"], sid_hint="WDX")
    alive = info.get("alive_http_ports") or []
    ports = {e["port"]: e for e in alive}
    assert 8090 in ports
    assert ports[8090]["status"] == "http_503"
    assert ports[8090]["https"] is False
    assert 44390 not in ports            # connection failure never qualifies


def test_c_http_200_no_rfcsi_recorded_as_alive(monkeypatch):
    """A 200 whose body lacks RFCSI (e.g. a WD landing page) is still a live
    web service → recorded."""
    _sapcontrol_silent(monkeypatch)
    _collect_pi(monkeypatch, status_by_port={44390: "http_200_no_rfcsi"})
    info = sapmap_scanner.enrich_system_info(
        "host.example", 3390, instance_nrs=["90"], sid_hint="WDX")
    ports = {e["port"]: e for e in (info.get("alive_http_ports") or [])}
    assert 44390 in ports
    assert ports[44390]["https"] is True


def test_c_parseable_port_not_double_recorded(monkeypatch):
    """A port that parses RFCSI (success) fills metadata and is NOT also
    logged as an unqualified alive port."""
    _sapcontrol_silent(monkeypatch)
    _collect_pi(monkeypatch, success_ports=(8090,))
    info = sapmap_scanner.enrich_system_info(
        "host.example", 3390, instance_nrs=["90"], sid_hint="WDX")
    ports = {e["port"] for e in (info.get("alive_http_ports") or [])}
    assert 8090 not in ports
    assert info.get("os_type") == "Linux"


# ===========================================================================
# C (consume) — _apply_alive_http_ports pure-helper
# ===========================================================================

def _node(sid="WDX", ip="10.0.0.1", instances=None):
    n = SAPNode(sid=sid, ip=ip, hostname="h")
    n.instances = instances if instances is not None else []
    return n


def _inst(instance_nr="90", ports=None, ip="10.0.0.1"):
    return InstanceInfo(instance_nr=instance_nr, ip=ip, ports=dict(ports or {}))


def test_apply_labels_http_and_https_on_matching_instance():
    node = _node(instances=[_inst("90", {3390: "gateway"})])
    q = sapmap_gui._apply_alive_http_ports(node, [
        {"inst_nr": 90, "port": 8090, "https": False, "status": "http_503"},
        {"inst_nr": 90, "port": 44390, "https": True, "status": "http_404"},
    ])
    ports = node.instances[0].ports
    assert ports[8090] == "icm_http"
    assert ports[44390] == "icm_https"
    assert set(q) == {(8090, "icm_http"), (44390, "icm_https")}


def test_apply_matches_two_digit_instance_from_int_nr():
    """inst_nr arrives as int 90 from the scanner; must match instance '90'."""
    node = _node(instances=[_inst("90", {})])
    sapmap_gui._apply_alive_http_ports(
        node, [{"inst_nr": 90, "port": 8090, "https": False,
                "status": "http_503"}])
    assert node.instances[0].ports[8090] == "icm_http"


def test_apply_falls_back_to_first_instance_when_nr_unmatched():
    """A bare web port (inst_nr 0) on an inst-90 node lands on the node's
    primary instance rather than being dropped."""
    node = _node(instances=[_inst("90", {3390: "gateway"})])
    sapmap_gui._apply_alive_http_ports(
        node, [{"inst_nr": 0, "port": 80, "https": False,
                "status": "http_503"}])
    assert node.instances[0].ports[80] == "icm_http"


def test_apply_creates_instance_when_node_has_none():
    node = _node(instances=[])
    q = sapmap_gui._apply_alive_http_ports(
        node, [{"inst_nr": 0, "port": 443, "https": True,
                "status": "http_200_no_rfcsi"}])
    assert len(node.instances) == 1
    assert node.instances[0].ports[443] == "icm_https"
    assert q == [(443, "icm_https")]


def test_apply_does_not_clobber_existing_wd_or_icm_label():
    node = _node(instances=[_inst("90", {8090: "wd_http", 44390: "icm_https"})])
    q = sapmap_gui._apply_alive_http_ports(node, [
        {"inst_nr": 90, "port": 8090, "https": False, "status": "http_503"},
        {"inst_nr": 90, "port": 44390, "https": True, "status": "http_404"},
    ])
    assert q == []                                  # nothing newly qualified
    assert node.instances[0].ports[8090] == "wd_http"
    assert node.instances[0].ports[44390] == "icm_https"


def test_apply_does_not_clobber_java_or_dispatcher_labels():
    """REGRESSION (adversarial review, HIGH): the helper must never relabel
    a port that already carries ANY service label — not just wd_/icm_.  On
    the re-run path a dual-stack node's java_http/java_https ICM ports 404
    on /sap/public/info and land in alive_http_ports; clobbering them to
    icm_* corrupts state and breaks the Java modules that locate the
    dispatcher by svc=='java_http'.  dispatcher/gateway likewise protected."""
    node = _node(instances=[_inst("80", {50080: "java_http",
                                         50081: "java_https",
                                         3280: "dispatcher"})])
    q = sapmap_gui._apply_alive_http_ports(node, [
        {"inst_nr": 80, "port": 50080, "https": False, "status": "http_404"},
        {"inst_nr": 80, "port": 50081, "https": True, "status": "http_404"},
        {"inst_nr": 80, "port": 3280, "https": False, "status": "http_404"},
    ])
    assert q == []                                   # nothing relabelled
    assert node.instances[0].ports[50080] == "java_http"
    assert node.instances[0].ports[50081] == "java_https"
    assert node.instances[0].ports[3280] == "dispatcher"


def test_apply_does_not_set_is_web_dispatcher():
    """A 4xx/5xx must not auto-assert WD — classification stays with the
    operator / fingerprint."""
    node = _node(instances=[_inst("90", {})])
    sapmap_gui._apply_alive_http_ports(
        node, [{"inst_nr": 90, "port": 8090, "https": False,
                "status": "http_503"}])
    assert node.is_web_dispatcher is False


@pytest.mark.parametrize("bad", [0, -1, 70000, "x", None])
def test_apply_skips_invalid_ports(bad):
    node = _node(instances=[_inst("90", {})])
    q = sapmap_gui._apply_alive_http_ports(
        node, [{"inst_nr": 90, "port": bad, "https": False,
                "status": "http_503"}])
    assert q == []
    assert node.instances[0].ports == {}


# ===========================================================================
# Source pins — the two operator routes are wired (closures can't be reached
# directly; same constraint/pattern as tests/test_wd_set_type_rediscover.py)
# ===========================================================================

def _route_body(name):
    src = inspect.getsource(sapmap_gui)
    m = re.search(
        rf"def {name}\([^)]*\):.*?(?=\n    @app\.route|\n    def )",
        src, re.DOTALL)
    assert m, f"{name} route body not found"
    return m.group(0)


def test_manual_add_route_wires_web_ports_and_alive_consume():
    body = _route_body("node_add")
    assert "include_web_ports=True" in body
    assert "_apply_alive_http_ports(" in body


def test_rerun_route_wires_web_ports_and_alive_consume():
    body = _route_body("node_rfc_system_info")
    assert "include_web_ports=True" in body
    assert "_apply_alive_http_ports(" in body


def test_enrich_default_leaves_web_ports_off():
    """The auto-scan default must stay False (no 80/443, unchanged scan)."""
    sig = inspect.signature(sapmap_scanner.enrich_system_info)
    assert sig.parameters["include_web_ports"].default is False
