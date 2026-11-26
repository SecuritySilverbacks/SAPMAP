"""_find_gw_port / _find_gw_ports_all return (host, port) from the SAME
instance (issue #246).

Issue #246 (same bug class as #164, reported by the same operator): the
gateway helpers in sapmap_exploit picked a port out of ``node.instances``
but every caller then paired it with ``node.ip or node.hostname`` — which
on a node whose instances live on DIFFERENT physical hosts (classic case:
node.ip is the Message-Server/ASCS host, the gateway instance is
elsewhere) is the wrong box.  The fix threads the owning instance's host
alongside the port:

  * ``_find_gw_port(node)``       → ``(host, port)``   (was: ``int``)
  * ``_find_gw_ports_all(node)``  → ``[(host, port)]`` (was: ``[int]``)

``host`` is ``inst.ip or inst.hostname or node.ip or node.hostname``,
resolved to an IPv4 dotted-quad (the GW SAPXPG packet builders feed
``socket.inet_aton``).  A new ``InstanceInfo.hostname`` field carries the
per-instance host for the one producer that genuinely spans hosts (the
Message-Server app-server import) and for the SAPology deep-scan bridge.

These tests pin the new contract and the host-travels-with-port invariant
at every layer: the two helpers, the probe branch, the integration path
through ``execute_gw_command``, the model round-trip, and the producers.
"""
import ast
import os
import re
import socket

import pytest

from sapmap_models import SAPNode, InstanceInfo
import sapmap_exploit as X


_EXPLOIT_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "exploitation", "sapmap_exploit.py",
)
_GUI_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "core", "sapmap_gui.py",
)
_SCANNER_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "discovery", "sapmap_scanner.py",
)


def _dual_host_node(sid="S4H"):
    """Node whose MS instance is on node.ip and whose gateway instance is
    on a DIFFERENT host — the #246 scenario."""
    n = SAPNode(sid=sid, ip="10.0.0.1", hostname="ascs.example")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1",
                     ports={3600: "message_server"}),
        InstanceInfo(instance_nr="01", ip="10.0.0.11",
                     ports={3301: "gateway"}),
    ]
    return n


# ---------------------------------------------------------------------------
# _find_gw_port — signature + host resolution
# ---------------------------------------------------------------------------

def test_find_gw_port_returns_host_port_tuple():
    host, port = X._find_gw_port(_dual_host_node())
    assert isinstance(host, str)
    assert isinstance(port, int)


def test_find_gw_port_uses_instance_host_not_node_ip():
    """The headline #246 fix: the returned host is the gateway instance's
    own ip, NOT node.ip (which is the MS host that doesn't expose a GW)."""
    assert X._find_gw_port(_dual_host_node()) == ("10.0.0.11", 3301)


def test_find_gw_port_falls_back_to_node_ip_when_instance_ip_empty():
    n = SAPNode(sid="NPL", ip="10.0.0.2", hostname="npl")
    n.instances = [InstanceInfo(instance_nr="00", ip="",
                                ports={3300: "gateway"})]
    assert X._find_gw_port(n) == ("10.0.0.2", 3300)


def test_find_gw_port_uses_instance_hostname_when_ip_empty():
    """inst.hostname is consulted before the node-level host."""
    n = SAPNode(sid="DEV", ip="", hostname="")
    n.instances = [InstanceInfo(instance_nr="00", ip="", hostname="127.0.0.1",
                                ports={3302: "gateway"})]
    assert X._find_gw_port(n) == ("127.0.0.1", 3302)


def test_find_gw_port_falls_back_to_node_hostname_resolved(monkeypatch):
    """When only node.hostname is available (an FQDN), it is resolved to an
    IPv4 dotted-quad for the packet builders."""
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda h: "192.0.2.50" if h == "srv.example" else
                        (_ for _ in ()).throw(socket.gaierror()))
    n = SAPNode(sid="SM1", ip="", hostname="srv.example")
    n.instances = [InstanceInfo(instance_nr="00", ip="",
                                ports={3300: "gateway"})]
    assert X._find_gw_port(n) == ("192.0.2.50", 3300)


def test_find_gw_port_unresolvable_host_returns_empty_host(monkeypatch):
    """A gateway port is known but its only host won't resolve → ("", port),
    so callers can emit a clean error instead of crashing inet_aton."""
    def _boom(h):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "gethostbyname", _boom)
    n = SAPNode(sid="X", ip="", hostname="does-not-resolve.invalid")
    n.instances = [InstanceInfo(instance_nr="00", ip="",
                                ports={3300: "gateway"})]
    assert X._find_gw_port(n) == ("", 3300)


def test_find_gw_port_no_gateway_returns_empty_and_zero():
    n = SAPNode(sid="X", ip="10.0.0.9")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.9",
                                ports={3600: "message_server"})]
    assert X._find_gw_port(n) == ("", 0)


def test_find_gw_port_no_instances_returns_empty_and_zero():
    n = SAPNode(sid="X", ip="10.0.0.9")
    assert X._find_gw_port(n) == ("", 0)


# ---------------------------------------------------------------------------
# _find_gw_port — cached vulnerable port
# ---------------------------------------------------------------------------

def test_find_gw_port_cached_port_uses_owning_instance_host():
    """The cached fast-path resolves the host of the instance that owns the
    cached port — not node.ip."""
    n = SAPNode(sid="C", ip="10.0.0.5", hostname="c")
    n.gw_vulnerable_port = 3303
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.5", ports={3600: "message_server"}),
        InstanceInfo(instance_nr="02", ip="10.0.0.55", ports={3303: "gateway"}),
    ]
    assert X._find_gw_port(n) == ("10.0.0.55", 3303)


def test_find_gw_port_cached_port_no_owning_instance_falls_back():
    """A cached port that no instance claims (legacy/hand-edited state)
    gracefully falls back to the node-level host."""
    n = SAPNode(sid="C", ip="10.0.0.7", hostname="c")
    n.gw_vulnerable_port = 3399
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.70",
                                ports={3300: "gateway"})]
    assert X._find_gw_port(n) == ("10.0.0.7", 3399)


# ---------------------------------------------------------------------------
# _find_gw_port — live probe branch (gw_vulnerable, >1 candidate)
# ---------------------------------------------------------------------------

def test_find_gw_port_probe_branch_connects_via_owning_instance_host(monkeypatch):
    """When probing to pick the responding port, each candidate is tried at
    ITS OWN instance host, and the winner's host is returned + cached."""
    tried = []

    class _FakeSock:
        def close(self):
            pass

    def _fake_connect(host, port, saprouter="", timeout=20):
        tried.append((host, port))
        # First candidate host refuses; second answers.
        if host == "10.0.0.11":
            return _FakeSock()
        raise ConnectionRefusedError()

    monkeypatch.setattr(X, "_gw_connect", _fake_connect)

    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.gw_vulnerable = True
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.10", ports={3300: "gateway"}),
        InstanceInfo(instance_nr="01", ip="10.0.0.11", ports={3301: "gateway"}),
    ]
    host, port = X._find_gw_port(n)
    assert (host, port) == ("10.0.0.11", 3301)
    # It probed the FIRST candidate at its own host (10.0.0.10), not node.ip.
    assert ("10.0.0.10", 3300) in tried
    assert ("10.0.0.11", 3301) in tried
    # Winning port is cached.
    assert n.gw_vulnerable_port == 3301


# ---------------------------------------------------------------------------
# _find_gw_ports_all — list of (host, port) pairs
# ---------------------------------------------------------------------------

def test_find_gw_ports_all_returns_host_port_pairs():
    pairs = X._find_gw_ports_all(_dual_host_node())
    assert pairs == [("10.0.0.11", 3301)]


def test_find_gw_ports_all_pairs_each_port_with_its_own_host():
    """Two gateway instances on two hosts → each port paired with its host,
    plain before SNC."""
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.10", ports={3300: "gateway"}),
        InstanceInfo(instance_nr="01", ip="10.0.0.11",
                     ports={4801: "gateway_snc"}),
    ]
    pairs = X._find_gw_ports_all(n)
    assert ("10.0.0.10", 3300) in pairs
    assert ("10.0.0.11", 4801) in pairs
    # plain (33XX) ordered before SNC (48XX)
    assert pairs.index(("10.0.0.10", 3300)) < pairs.index(("10.0.0.11", 4801))


def test_find_gw_ports_all_cached_port_first_with_owning_host():
    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.gw_vulnerable_port = 3301
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.10", ports={3300: "gateway"}),
        InstanceInfo(instance_nr="01", ip="10.0.0.11", ports={3301: "gateway"}),
    ]
    pairs = X._find_gw_ports_all(n)
    assert pairs[0] == ("10.0.0.11", 3301)


def test_find_gw_ports_all_drops_unresolvable_host(monkeypatch):
    """A candidate whose host cannot be resolved is dropped from the list
    (the resolver logs it), rather than crashing the probe chain."""
    def _resolve(h):
        if h == "10.0.0.10":
            return h
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "gethostbyname", _resolve)

    n = SAPNode(sid="S4H", ip="10.0.0.1")
    n.instances = [
        # ip is already dotted-quad → returned as-is
        InstanceInfo(instance_nr="00", ip="10.0.0.10", ports={3300: "gateway"}),
        # hostname only, won't resolve → dropped
        InstanceInfo(instance_nr="01", ip="", hostname="bad.invalid",
                     ports={3301: "gateway"}),
    ]
    pairs = X._find_gw_ports_all(n)
    assert pairs == [("10.0.0.10", 3300)]


def test_find_gw_ports_all_empty_when_no_candidates():
    n = SAPNode(sid="X", ip="10.0.0.9")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.9",
                                ports={3600: "message_server"})]
    assert X._find_gw_ports_all(n) == []


# ---------------------------------------------------------------------------
# Integration — execute_gw_command connects to the instance host
# ---------------------------------------------------------------------------

def test_execute_gw_command_connects_to_instance_host_not_node_ip(monkeypatch):
    """The hot-path exec primitive must open its socket against the gateway
    instance's host, not node.ip."""
    captured = {}

    def _fake_connect(host, port, saprouter="", timeout=20):
        captured["host"] = host
        captured["port"] = port
        raise ConnectionRefusedError("stop here — host already captured")

    monkeypatch.setattr(X, "_gw_connect", _fake_connect)

    n = _dual_host_node()
    result = X.execute_gw_command(n, "id")
    assert captured["host"] == "10.0.0.11"   # the GW instance host
    assert captured["port"] == 3301
    # The connect raised, so the call reports failure (we only assert the
    # endpoint selection here).
    assert result["success"] is False


def test_execute_gw_command_errors_cleanly_when_host_unresolvable(monkeypatch):
    def _boom(h):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "gethostbyname", _boom)
    n = SAPNode(sid="X", ip="", hostname="nope.invalid")
    n.instances = [InstanceInfo(instance_nr="00", ip="",
                                ports={3300: "gateway"})]
    result = X.execute_gw_command(n, "id")
    assert result["success"] is False
    assert "reachable host" in result["error"]


def test_execute_gw_command_no_gateway_reports_no_port():
    n = SAPNode(sid="X", ip="10.0.0.9")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.9",
                                ports={3600: "message_server"})]
    result = X.execute_gw_command(n, "id")
    assert result["success"] is False
    assert "No gateway port" in result["error"]


# ---------------------------------------------------------------------------
# Label contract — _build_java_os_exec shows the instance host:port
# ---------------------------------------------------------------------------

def test_build_java_os_exec_label_shows_instance_host_and_port():
    n = _dual_host_node(sid="JAVA")
    n.system_type = "ABAP+JAVA"
    n.gw_vulnerable = True
    fn, label, err = X._build_java_os_exec(n)
    assert err == ""
    assert "10.0.0.11:3301" in label   # instance host:port, not node.ip


# ---------------------------------------------------------------------------
# Model — InstanceInfo.hostname round-trips
# ---------------------------------------------------------------------------

def test_instance_info_hostname_round_trips():
    inst = InstanceInfo(instance_nr="01", ip="10.0.0.11",
                        hostname="app01.example", ports={3301: "gateway"})
    d = inst.to_dict()
    assert d["hostname"] == "app01.example"
    restored = InstanceInfo.from_dict(d)
    assert restored.hostname == "app01.example"


def test_instance_info_hostname_defaults_empty_on_legacy_load():
    """A legacy .sapmap instance dict with no hostname key loads to ""."""
    d = InstanceInfo(instance_nr="00", ip="10.0.0.1").to_dict()
    d.pop("hostname", None)
    restored = InstanceInfo.from_dict(d)
    assert restored.hostname == ""


def test_node_round_trip_preserves_instance_hostname():
    from sapmap_models import SAPMAPState
    n = _dual_host_node()
    n.instances[1].hostname = "app01.example"
    state = SAPMAPState()
    state.add_node(n)
    import json
    restored = SAPMAPState.from_dict(json.loads(state.to_json()))
    rnode = restored.get_node("S4H")
    hosts = {i.instance_nr: i.hostname for i in rnode.instances}
    assert hosts["01"] == "app01.example"


# ---------------------------------------------------------------------------
# Producers — source pins (the writers that make the fix bite)
# ---------------------------------------------------------------------------

def test_ms_import_producer_populates_instance_hostname():
    src = open(_GUI_SRC_PATH, encoding="utf-8").read()
    # The MS app-server import must stamp the per-server FQDN as hostname.
    assert "hostname=fqdn_host" in src


def test_sapology_bridge_populates_instance_hostname():
    src = open(_SCANNER_SRC_PATH, encoding="utf-8").read()
    assert 'hostname=getattr(inst, "host", "") or ""' in src


# ---------------------------------------------------------------------------
# Source pins — the signature change + no caller re-derives host
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def exploit_src():
    return open(_EXPLOIT_SRC_PATH, encoding="utf-8").read()


def test_find_gw_port_signature_is_tuple(exploit_src):
    assert "def _find_gw_port(node: SAPNode) -> tuple:" in exploit_src


def test_find_gw_ports_all_signature_unchanged_list(exploit_src):
    assert "def _find_gw_ports_all(node: SAPNode) -> list:" in exploit_src


def test_callers_unpack_host_and_port(exploit_src):
    """Every in-scope caller takes host from _find_gw_port rather than
    computing node.ip or node.hostname next to the call."""
    # execute_gw_command, create_user_gw_exploit, dpmon
    assert exploit_src.count("host, gw_port = _find_gw_port(node)") >= 3
    # the two display sites unpack too
    assert "_gw_host, _gw_port = _find_gw_port(node)" in exploit_src
    assert "_gw_host, gw_port = _find_gw_port(node)" in exploit_src


def test_no_find_gw_port_bare_int_return(exploit_src):
    """Guard against a regression that reverts to the bare-int return."""
    assert "return node.gw_vulnerable_port\n" not in exploit_src
    assert re.search(r"return candidates\[0\]\s*\n", exploit_src) is None


# ---------------------------------------------------------------------------
# Consistency — the GW-write host and the RFC-verify host agree (#246/#164)
# ---------------------------------------------------------------------------

def test_rfc_connection_uses_instance_hostname_matching_gw_path(monkeypatch):
    """create_user_gw_exploit writes via the GW to _gw_inst_host (which
    consults inst.hostname), then verifies via RFC through
    sapmap_rfc._get_connection — which must reach the SAME box.  For an
    MS-imported instance that carries a hostname but no ip, _get_connection
    must pick inst.hostname, not fall back to node.ip (the MS host)."""
    import sapmap_rfc as srfc
    import sap_rfc_ctypes as _ctypes_mod
    from sapmap_models import SAPNode, Credentials, InstanceInfo

    # Force the C backend so _get_connection instantiates RFCConnection.
    # Everything is monkeypatched (auto-reverted) — no module reload and no
    # set_sdk_path(), so no state leaks into later tests.
    monkeypatch.setattr(_ctypes_mod, "is_sdk_loadable",
                        lambda sdk_path="": True)
    monkeypatch.setattr(srfc, "_use_pure_rfc", False)
    monkeypatch.setattr(srfc, "_sdk_path", "/opt/nwrfcsdk/lib")

    captured = {}

    class _FakeConn:
        def __init__(self, **kwargs):
            captured.clear()
            captured.update(kwargs)
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(_ctypes_mod, "RFCConnection", _FakeConn)

    # MS-imported app server: hostname set, ip empty.  node.ip is the MS host.
    node = SAPNode(sid="S4H", ip="10.0.0.1", hostname="ascs.example",
                   instances=[InstanceInfo(instance_nr="01", ip="",
                                           hostname="app01.example")])
    creds = Credentials(username="u", password="x", client="001",
                        instance_nr="01")
    srfc._get_connection(node, creds)
    assert captured["ashost"] == "app01.example"

    # Same instance via the GW path resolves to the same host string.
    assert X._gw_inst_host(node.instances[0], node) == "app01.example"
