"""Endpoint pickers pair the HOST with the owning-instance port (issue #255).

Follow-up to #246 (and its sibling #164).  #246 fixed the "port picked from
an instance, host taken from ``node.ip``" pattern for the GW SAPXPG path by
threading the owning instance's host alongside the port in
``_find_gw_port`` / ``_find_gw_ports_all``.  #255 extends the same invariant
to the OTHER endpoint pickers:

  * Java-HTTP:        ``_find_java_http_endpoint(node) → (host, port, https)``
  * DIAG dispatcher:  ``_find_dispatcher_endpoint(node) → (host, port, instance_nr)``
  * Primitive:        ``_inst_host(inst, node) → str`` (the non-GW analogue
                       of ``_gw_inst_host``; no IPv4 resolution — DIAG/HTTP
                       paths accept hostnames natively).

Plus a sibling in ``sapmap_rfc`` that pairs the SNC-aware
``_resolve_gateway_service`` port with its owning-instance host for the
self-referencing SAPXPG TCP/IP destination (and its cross-system GUI twin):

  * ``_sapxpg_dest_host(node, gw_port) → str``

These tests pin the new contracts, the host-travels-with-port invariant at
each layer, and the caller-level regressions (CVE scanners, dispatcher
sweep targets, SAPXPG dest) that silently pointed at the wrong box on a
multi-host node before #255.

Lesson carried over from #246's test file: do NOT reload modules with
``del sys.modules[...]`` + reimport — ``set_sdk_path`` and similar module-
global mutators leak into later alphabetically-sorted tests (broke
test_java_deploy_helpers::TestCheckReusable previously).  All patching
here goes through ``monkeypatch`` so pytest auto-reverts it.
"""
import ast
import os
import socket

import pytest

from sapmap_models import SAPNode, InstanceInfo
import sapmap_exploit as X


_EXPLOIT_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "exploitation", "sapmap_exploit.py",
)
_SCANNER_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "discovery", "sapmap_scanner.py",
)


def _dual_host_java_node(sid="S4H"):
    """Multi-host node whose MS lives on node.ip and whose AS-Java /
    dispatcher instance lives elsewhere — the #255 scenario."""
    n = SAPNode(sid=sid, ip="10.0.0.1", hostname="ascs.example")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1",
                     ports={3600: "message_server"}),
        InstanceInfo(instance_nr="05", ip="10.0.0.5",
                     hostname="app05.example",
                     ports={3205: "dispatcher",
                            3305: "gateway",
                            50500: "java_http"}),
    ]
    return n


# ---------------------------------------------------------------------------
# _inst_host — the primitive
# ---------------------------------------------------------------------------

def test_inst_host_prefers_instance_ip():
    n = _dual_host_java_node()
    inst05 = n.instances[1]
    assert X._inst_host(inst05, n) == "10.0.0.5"


def test_inst_host_falls_through_to_instance_hostname():
    n = SAPNode(sid="S", ip="10.0.0.1")
    inst = InstanceInfo(instance_nr="02", ip="", hostname="app02.lab",
                        ports={})
    assert X._inst_host(inst, n) == "app02.lab"


def test_inst_host_falls_through_to_node_ip_then_hostname():
    n = SAPNode(sid="S", ip="10.0.0.1", hostname="node.lab")
    empty = InstanceInfo(instance_nr="02", ports={})
    assert X._inst_host(empty, n) == "10.0.0.1"

    n2 = SAPNode(sid="S", ip="", hostname="node.lab")
    assert X._inst_host(empty, n2) == "node.lab"

    n3 = SAPNode(sid="S", ip="", hostname="")
    assert X._inst_host(empty, n3) == ""


def test_inst_host_does_NOT_resolve_hostname_to_ipv4():
    """DIAG/HTTP paths accept hostnames natively — resolving here would be
    an unnecessary behaviour change that could break hostname-only targets
    that only resolve inside the operator's network."""
    n = SAPNode(sid="S", ip="", hostname="")
    inst = InstanceInfo(instance_nr="00", ip="", hostname="srv.example",
                        ports={})
    # Hostname passes through unchanged, no DNS lookup attempted.
    assert X._inst_host(inst, n) == "srv.example"


# ---------------------------------------------------------------------------
# _find_java_http_endpoint — signature + priority order
# ---------------------------------------------------------------------------

def test_find_java_http_endpoint_signature():
    host, port, https = X._find_java_http_endpoint(_dual_host_java_node())
    assert isinstance(host, str)
    assert isinstance(port, int)
    assert isinstance(https, bool)


def test_find_java_http_endpoint_uses_owning_instance_host():
    """The headline #255 fix for the Java-HTTP side: when a java_http port
    lives on instance 05 (ip 10.0.0.5), the returned host is 10.0.0.5 —
    NOT node.ip (10.0.0.1, the MS box)."""
    n = _dual_host_java_node()
    host, port, https = X._find_java_http_endpoint(n)
    assert (host, port) == ("10.0.0.5", 50500)


def test_find_java_http_endpoint_ignores_cve_scalars():
    """Adversarial review of the first #255 cut caught three distinct ways
    baking CVE-scalar priorities INTO the helper went wrong (cross-CVE
    scheme mismatch for RECON, legacy 6287>31324 flip for CTC, and
    HTTPS-on-patched-node for secstore).  The fix: the helper is label +
    convention only; callers inline their own per-CVE rule.  This test
    pins that contract."""
    n = _dual_host_java_node()
    # Clear the labelled java_http so convention is the only remaining
    # source and CVE scalars must not sneak in.
    del n.instances[1].ports[50500]
    n.cve_2025_31324_port = 50501
    n.cve_2025_31324_https = True
    n.cve_2020_6287_port = 51500
    n.cve_2020_6287_https = False
    # Neither CVE scalar's port (50501/51500) appears in the result —
    # the helper falls through to convention (50000 from instance 00).
    host, port, https = X._find_java_http_endpoint(n)
    assert port != 50501 and port != 51500
    assert port == 50000  # convention from instance 00
    assert host == "10.0.0.1"


def test_find_java_http_endpoint_prefer_https_kwarg():
    """When a caller knows it wants HTTPS (e.g. an operator-forced
    channel), the ``prefer="https"`` kwarg flips java_https ahead of
    java_http.  Default ``prefer="http"`` keeps the pre-#255 preference."""
    n = SAPNode(sid="J", ip="10.0.0.1")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={50000: "java_http",
                                        50001: "java_https"})]
    assert X._find_java_http_endpoint(n) == ("10.0.0.1", 50000, False)
    assert X._find_java_http_endpoint(n, prefer="https") == (
        "10.0.0.1", 50001, True)


def test_host_for_port_resolves_owning_instance():
    """_host_for_port is exported so CVE-scalar callers can resolve the
    host of the instance that owns a cached CVE port."""
    n = _dual_host_java_node()
    assert X._host_for_port(n, 50500) == "10.0.0.5"
    # Unknown port falls back to node.ip (single-host-safe default).
    assert X._host_for_port(n, 60000) == "10.0.0.1"


def test_find_java_http_endpoint_falls_back_to_convention():
    """No CVE scalar and no labelled port → 5NN00 derived from first
    instance nr, with THAT instance's host (not node.ip)."""
    n = SAPNode(sid="J", ip="10.0.0.1", hostname="ms")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1", ports={}),
        InstanceInfo(instance_nr="07", ip="10.0.0.7",
                     ports={3207: "dispatcher"}),
    ]
    host, port, https = X._find_java_http_endpoint(n)
    # First instance that yields a convention port wins (nr=00 → 50000)
    assert (host, port, https) == ("10.0.0.1", 50000, False)


def test_find_java_http_endpoint_no_data_returns_empty_tuple():
    n = SAPNode(sid="X", ip="", hostname="")
    assert X._find_java_http_endpoint(n) == ("", 0, False)


# ---------------------------------------------------------------------------
# _find_dispatcher_endpoint — signature + host from the owning instance
# ---------------------------------------------------------------------------

def test_find_dispatcher_endpoint_signature():
    host, port, inst_nr = X._find_dispatcher_endpoint(_dual_host_java_node())
    assert isinstance(host, str)
    assert isinstance(port, int)
    assert isinstance(inst_nr, str)


def test_find_dispatcher_endpoint_uses_owning_instance_host():
    """#255 for dispatcher: the dispatcher port lives on instance 05
    (ip 10.0.0.5), so the returned host is 10.0.0.5 — NOT node.ip."""
    n = _dual_host_java_node()
    assert X._find_dispatcher_endpoint(n) == ("10.0.0.5", 3205, "05")


def test_find_dispatcher_endpoint_via_svc_label():
    """Non-32XX port carrying the ``dispatcher`` label is accepted
    (mirrors _node_dispatcher_port's existing contract)."""
    n = SAPNode(sid="S", ip="10.0.0.1")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={3299: "dispatcher"})]
    assert X._find_dispatcher_endpoint(n) == ("10.0.0.1", 3299, "00")


def test_find_dispatcher_endpoint_no_dispatcher_returns_empty():
    n = SAPNode(sid="S", ip="10.0.0.1")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={3600: "message_server"})]
    assert X._find_dispatcher_endpoint(n) == ("", 0, "")


def test_find_dispatcher_endpoint_does_not_blind_guess_3200():
    """Unlike the pre-#255 world, no instance means no dispatcher — don't
    conjure 3200+NN out of thin air."""
    n = SAPNode(sid="S", ip="10.0.0.1")
    assert X._find_dispatcher_endpoint(n) == ("", 0, "")


# ---------------------------------------------------------------------------
# sapmap_rfc._sapxpg_dest_host — SNC-aware port pairs with owning host
# ---------------------------------------------------------------------------

def test_sapxpg_dest_host_pairs_with_owning_gateway_instance():
    import sapmap_rfc as R
    n = SAPNode(sid="T", ip="10.0.0.1", hostname="ms")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1",
                     ports={3601: "sapms"}),
        InstanceInfo(instance_nr="05", ip="10.0.0.5",
                     ports={3305: "gateway"}),
    ]
    port = R._resolve_gateway_service(n)
    assert port == "3305"
    # #255 — the host must be 10.0.0.5 (owning instance of 3305), NOT
    # node.ip (10.0.0.1, the MS box that doesn't expose the gateway).
    assert R._sapxpg_dest_host(n, port) == "10.0.0.5"


def test_sapxpg_dest_host_snc_port_pairs_with_owning_instance():
    """SNC-aware pick — _resolve_gateway_service selects a 48NN port when
    SNC is configured; _sapxpg_dest_host must carry THAT instance's host."""
    import sapmap_rfc as R
    n = SAPNode(sid="T", ip="10.0.0.1", snc_partnername="p:CN=X")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1", ports={}),
        InstanceInfo(instance_nr="03", ip="10.0.0.3",
                     ports={4803: "gateway_snc"}),
    ]
    port = R._resolve_gateway_service(n, snc=True)
    assert port == "4803"
    assert R._sapxpg_dest_host(n, port) == "10.0.0.3"


def test_sapxpg_dest_host_falls_back_when_port_unknown():
    """When _resolve_gateway_service derived a fallback port that no
    instance owns, pre-#255 behaviour (node.ip) is restored."""
    import sapmap_rfc as R
    n = SAPNode(sid="T", ip="10.0.0.9", hostname="fallback.lab")
    # No instance owns port 3399
    assert R._sapxpg_dest_host(n, "3399") == "10.0.0.9"


# ---------------------------------------------------------------------------
# Dispatcher-caller regressions: pwspray + logon_sweep keep their
# legacy shapes AND their new owning-host behaviour.
# ---------------------------------------------------------------------------

def test_pwspray_node_dispatcher_port_wrapper_still_returns_int():
    """Pre-#255 callers of pwspray._node_dispatcher_port get a bare int."""
    import sapmap_pwspray as pw
    assert pw._node_dispatcher_port(_dual_host_java_node()) == 3205


def test_logon_sweep_node_dispatcher_port_wrapper_still_returns_tuple():
    """Pre-#255 callers of logon_sweep._node_dispatcher_port get
    (port, instance_nr)."""
    import sapmap_logon_sweep as ls
    assert ls._node_dispatcher_port(_dual_host_java_node()) == (3205, "05")


def test_logon_sweep_enumerate_targets_uses_owning_host():
    """The real #255 win in logon_sweep: the enumerated target's host is
    the dispatcher instance's own host, not node.ip."""
    import sapmap_logon_sweep as ls
    from sapmap_logon_sweep import LogonSweepConfig
    from sapmap_models import SAPMAPState

    class _S:
        pass
    s = SAPMAPState()
    n = _dual_host_java_node()
    n.system_type = "ABAP"  # scope gate
    s.nodes = {n.sid: n}
    cfg = LogonSweepConfig(single_sid=n.sid)
    targets = ls.enumerate_targets(s, cfg)
    assert len(targets) == 1
    assert targets[0]["host"] == "10.0.0.5"
    assert targets[0]["port"] == 3205
    assert targets[0]["instance_nr"] == "05"


def test_pwspray_build_target_matrix_uses_owning_host():
    """Same for pwspray: the SprayTarget.host is the dispatcher instance's
    own host, and the two ineligibility reasons stay distinct."""
    import sapmap_pwspray as pw
    from sapmap_models import SAPMAPState

    s = SAPMAPState()
    n = _dual_host_java_node()
    n.system_type = "ABAP"
    n.clients = [{"nr": "001"}]
    s.nodes = {n.sid: n}
    r = pw.build_target_matrix(s, {"single_sid": n.sid})
    assert len(r["eligible"]) == 1
    t = r["eligible"][0]
    assert t.host == "10.0.0.5"
    assert t.dispatcher_port == 3205


# ---------------------------------------------------------------------------
# _gateway_port_reachable: delegates to _find_gw_port → multi-host win
# ---------------------------------------------------------------------------

def test_gateway_port_reachable_targets_owning_instance(monkeypatch):
    """Pre-#255 this probed node.ip:33NN of the first instance, so on a
    multi-host node it silently failed and pre-empted the (correct)
    GW path.  Post-#255 it targets the gateway instance's own host."""
    n = _dual_host_java_node()
    n.gw_vulnerable = True
    # Dummy socket that records the (host, port) the probe tried.
    attempts = []

    class _FakeSock:
        def settimeout(self, t): pass
        def connect(self, addr): attempts.append(addr)
        def close(self): pass

    monkeypatch.setattr("socket.socket",
                        lambda *a, **k: _FakeSock())
    assert X._gateway_port_reachable(n) is True
    assert attempts == [("10.0.0.5", 3305)]  # NOT ("10.0.0.1", 3300)


# ---------------------------------------------------------------------------
# Signature source pins — stop later drift / silent contract changes.
# ---------------------------------------------------------------------------

def _func_arg_count(src_path: str, func_name: str) -> int:
    with open(src_path) as f:
        tree = ast.parse(f.read(), filename=src_path)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return len(node.args.args)
    raise AssertionError(f"{func_name} not found in {src_path}")


def test_find_java_http_endpoint_signature_pin():
    # (node, prefer="http") — the prefer kwarg was added in the
    # adversarial-review follow-up so callers can request https-first.
    assert _func_arg_count(_EXPLOIT_SRC_PATH, "_find_java_http_endpoint") == 2


def test_find_dispatcher_endpoint_signature_pin():
    assert _func_arg_count(_EXPLOIT_SRC_PATH, "_find_dispatcher_endpoint") == 1


def test_inst_host_signature_pin():
    assert _func_arg_count(_EXPLOIT_SRC_PATH, "_inst_host") == 2


def test_find_java_http_endpoint_present_in_source():
    """Guards against a rename that would hide the #255 helper from its
    callers (which import it by name)."""
    with open(_EXPLOIT_SRC_PATH) as f:
        src = f.read()
    assert "def _find_java_http_endpoint" in src
    assert "def _find_dispatcher_endpoint" in src
    assert "def _inst_host" in src


# ---------------------------------------------------------------------------
# CVE-scanner candidate-tuple shape — ensure host travels per-candidate.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fn_name", [
    "check_cve_2025_31324",
    "check_cve_2020_6287",
    "check_cve_2022_22536",
])
def test_cve_scanner_candidates_carry_host(fn_name):
    """The CVE-scanner candidate lists are now (host, port, use_https)
    tuples (three fields), not (port, use_https).  Pins the shape so a
    future revert can't silently reintroduce the #255 mismatch."""
    with open(_SCANNER_SRC_PATH) as f:
        src = f.read()
    # Locate the function body and search it for the new unpacking shape.
    tree = ast.parse(src, filename=_SCANNER_SRC_PATH)
    body = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            body = ast.get_source_segment(src, node)
            break
    assert body, f"{fn_name} not found"
    # Every scanner must iterate (host, port, use_https) now.
    assert "for host, port, use_https in candidates" in body, (
        f"{fn_name} should unpack three-tuple candidates post-#255")


# ---------------------------------------------------------------------------
# Round-trip: multi-host state survives to_dict/from_dict (regression
# guard — the new producers rely on InstanceInfo.hostname surviving a
# .sapmap save/load).
# ---------------------------------------------------------------------------

def test_dual_host_node_roundtrip_preserves_instance_host():
    n = _dual_host_java_node()
    d = n.to_dict()
    n2 = SAPNode.from_dict(d)
    assert len(n2.instances) == 2
    # The gateway instance's ip survives.
    assert n2.instances[1].ip == "10.0.0.5"
    assert n2.instances[1].hostname == "app05.example"
    # And the helpers still pick the owning-instance host after reload.
    assert X._find_java_http_endpoint(n2)[0] == "10.0.0.5"
    assert X._find_dispatcher_endpoint(n2)[0] == "10.0.0.5"


# ---------------------------------------------------------------------------
# Adversarial-review regressions — one test per confirmed finding so a
# future refactor that reintroduces the bug fails loudly.
# ---------------------------------------------------------------------------

def test_mark_java_http_port_targets_owning_instance_on_multihost():
    """Finding #8/#12 — _mark_java_http_port without a host hint still
    lands on the first instance (back-compat), but WITH a host hint it
    writes onto the matching instance so a multi-host node's confirmed
    port lands on the Java box, not the MS/ASCS box."""
    n = _dual_host_java_node()
    # host="10.0.0.5" matches instance 05 (the Java box).
    X._mark_java_http_port(n, 55555, host="10.0.0.5")
    # Instance 00 (MS box) should NOT have 55555.
    assert 55555 not in n.instances[0].ports
    # Instance 05 (Java box) should.
    assert n.instances[1].ports.get(55555) == "java_http"


def test_mark_java_http_port_without_host_falls_back_to_first_instance():
    """Back-compat: callers that don't pass a host (legacy callers) still
    land on the first instance with a dict ports map."""
    n = _dual_host_java_node()
    X._mark_java_http_port(n, 55555)
    assert n.instances[0].ports.get(55555) == "java_http"


def test_find_java_http_endpoint_patched_node_does_not_promote_https():
    """Finding #6 — on a patched node (cve_2025_31324_vulnerable=False)
    whose scanner still recorded cve_2025_31324_port=50001 (HTTPS)
    for display, the helper MUST NOT silently return HTTPS/50001.
    Instead it uses the labelled java_http or convention plain-HTTP."""
    n = SAPNode(sid="J", ip="10.0.0.1")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={50000: "java_http",
                                        50001: "java_https"})]
    n.cve_2025_31324_vulnerable = False
    n.cve_2025_31324_port = 50001  # display-only scalar
    n.cve_2025_31324_https = True
    host, port, https = X._find_java_http_endpoint(n)
    # Plain HTTP wins — the Connection-reset trap on the TLS port is
    # avoided even though the CVE scalar suggests HTTPS.
    assert (port, https) == (50000, False)


def test_find_java_http_endpoint_empty_instances_returns_empty():
    """Finding-adjacent: convention step MUST NOT fire against a node
    with no instances (returning a bogus host, 50000, False would make
    every caller connect to node.ip:50000 blindly)."""
    n = SAPNode(sid="X", ip="10.0.0.1", hostname="h")
    assert X._find_java_http_endpoint(n) == ("", 0, False)


def test_create_user_via_ticket_empty_instances_default_port(monkeypatch):
    """Finding #1 (nit) — the empty-instances fallback must still yield
    the conventional 8000/44300 port, not 0, so an unscanned BTPDISC
    placeholder target gets the pre-#255 long-shot default instead of
    an immediate port-0 connect error."""
    import ast as _ast
    with open(_EXPLOIT_SRC_PATH) as f:
        tree = _ast.parse(f.read(), filename=_EXPLOIT_SRC_PATH)
    src = ""
    for node in _ast.walk(tree):
        if (isinstance(node, _ast.FunctionDef)
                and node.name == "create_user_via_ticket"):
            src = _ast.get_source_segment(open(_EXPLOIT_SRC_PATH).read(),
                                            node)
            break
    assert src, "create_user_via_ticket not found"
    # The `and target_node.instances` conjunct must NOT guard the port
    # derivation (the first #255 cut had it; adversarial review caught
    # that it left http_port=0 on empty instances).
    assert "if not http_port and target_node.instances:" not in src, (
        "empty-instances fallback must still assign http_port (not 0) — "
        "see adversarial-review finding #1")


def test_cve_scanners_backfill_owning_instance_port(monkeypatch):
    """Finding #3/#7 — when a CVE scanner confirms a vulnerable port,
    it MUST stamp the port into the owning instance's inst.ports so
    _host_for_port downstream resolves to the right box instead of
    falling back to node.ip."""
    import sapmap_scanner as S
    n = _dual_host_java_node()
    n.system_type = "JAVA"
    # Pretend the sapcontrol+discovery already found Java HTTP on inst 05.
    n.instances[1].ports[50500] = "java_http"

    # Stub reachability + CVE probe.
    monkeypatch.setattr(S, "_scan_port", lambda h, p, timeout=0: True)
    class _FakeProbe:
        def __call__(self, h, p, use_https=False, timeout=10):
            # Vulnerable iff probing the Java-box host.
            return {"reachable": True,
                    "vulnerable": (h == "10.0.0.5" and p == 50500),
                    "evidence": "stub"}
    monkeypatch.setattr("sap_cve_2025_31324.check_cve_2025_31324",
                         _FakeProbe())
    S.check_cve_2025_31324(n, timeout=1)
    # Port 50500 was already on inst 05 — scanner's backfill via
    # _mark_java_http_port(..., host="10.0.0.5") must not corrupt the
    # label (it was already "java_http"; stays that way).
    assert n.instances[1].ports.get(50500) == "java_http"
    # Spot-check: _host_for_port resolves to the owning box.
    assert X._host_for_port(n, 50500) == "10.0.0.5"


def test_telnet_cve_candidate_pairs_with_owning_host():
    """Finding #11 — the CVE-31324-derived telnet candidate must be
    probed at the owning instance's host, not node.ip (which post-#255
    scanner backfill is NOT guaranteed to equal the CVE instance's
    host on a multi-host node)."""
    n = _dual_host_java_node()
    # Pretend the CVE scanner landed on 50500 (instance 05, host 10.0.0.5).
    n.cve_2025_31324_port = 50500
    cands = X._candidate_telnet_endpoints(n)
    # At least one candidate must be at 10.0.0.5 (the Java box),
    # specifically the CVE-derived one (50008 + 5*100 = 50508).
    assert ("10.0.0.5", 50508) in cands, cands
