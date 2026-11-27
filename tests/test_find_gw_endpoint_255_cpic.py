"""_find_gw_endpoint surfaces the owning instance's hostname, and every
P2/P3/P4 build_p2 call now passes it as target_hostname (issue #255 part
3 — kernel-793 CPIC long_lu fix on multi-host nodes).

Background.  Kernel 793's gateway silently invalidates the conv_id when
the ``long_lu`` field derived from the hostname does not match the
gateway's own hostname.  Pre-#255-part-3, every P2 was built with
``target_hostname = node.hostname or host`` — on a multi-host node whose
gateway lives on an app-server instance, long_lu was derived from the
central-services hostname while sapgwNN advertised the app-server one,
so P3 failed with "Conversation NNNNNNNN not found".

This commit extends _find_gw_port's 2-tuple into _find_gw_endpoint's
4-tuple ``(host, port, hostname, instance_nr)``, all sourced from the
same owning instance.  _find_gw_port stays a thin 2-tuple wrapper so
#246's contract is unchanged.  The 5 ``target_hostname=hostname`` build
sites (two in sapmap_exploit + three DB-writer calls in create_user_gw_
exploit that thread into build_p2/p3/p4 inside sap_db_sql_writers) now
pull the hostname via _gw_hostname_for_port.

Tests here pin:
  * _find_gw_endpoint's return shape and multi-host correctness;
  * _find_gw_port remains a 2-tuple wrapper that matches
    _find_gw_endpoint[:2] exactly;
  * _gw_hostname_for_port's precedence (inst.hostname -> node.hostname
    -> inst.ip -> node.ip) so single-host nodes get the pre-#255-part-3
    value and the single-host regression never slips in;
  * every P2/P3/P4 target_hostname source in the exploit module now
    comes from _gw_hostname_for_port, not node.hostname.
"""
import ast
import os

import pytest

from sapmap_models import SAPNode, InstanceInfo
import sapmap_exploit as X


_EXPLOIT_SRC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "exploitation", "sapmap_exploit.py",
)


def _dual_host_gw_node(sid="S4H"):
    """MS/ASCS on node.ip, gateway on a different box with its own FQDN."""
    n = SAPNode(sid=sid, ip="10.0.0.1", hostname="ms.example")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1",
                     ports={3601: "sapms"}),
        InstanceInfo(instance_nr="05", ip="10.0.0.5",
                     hostname="app05.example",
                     ports={3305: "gateway"}),
    ]
    return n


# ---------------------------------------------------------------------------
# _find_gw_endpoint contract — 4-tuple, host/port/hostname/instance_nr all
# from the same owning instance.
# ---------------------------------------------------------------------------

def test_find_gw_endpoint_signature_4tuple():
    r = X._find_gw_endpoint(_dual_host_gw_node())
    assert len(r) == 4
    host, port, hostname, inst_nr = r
    assert isinstance(host, str)
    assert isinstance(port, int)
    assert isinstance(hostname, str)
    assert isinstance(inst_nr, str)


def test_find_gw_endpoint_multi_host_all_from_owning_instance():
    """The headline PR-B fix: hostname and instance_nr both come from the
    GATEWAY instance, not from the MS one at node.ip."""
    n = _dual_host_gw_node()
    assert X._find_gw_endpoint(n) == ("10.0.0.5", 3305, "app05.example", "05")


def test_find_gw_port_remains_two_tuple_wrapper():
    """#246's contract is unchanged — _find_gw_port returns (host, port)
    and matches _find_gw_endpoint[:2] exactly."""
    n = _dual_host_gw_node()
    assert X._find_gw_port(n) == X._find_gw_endpoint(n)[:2]
    # And on a no-GW node both agree on the empty case.
    empty = SAPNode(sid="X")
    assert X._find_gw_port(empty) == ("", 0)
    assert X._find_gw_endpoint(empty) == ("", 0, "", "")


def test_find_gw_endpoint_cached_port_fast_path():
    """gw_vulnerable_port cache fast-path also surfaces owning hostname."""
    n = _dual_host_gw_node()
    n.gw_vulnerable_port = 3305
    assert X._find_gw_endpoint(n) == ("10.0.0.5", 3305, "app05.example", "05")


# ---------------------------------------------------------------------------
# _gw_hostname_for_port precedence — single-host regression guard.
# ---------------------------------------------------------------------------

def test_gw_hostname_for_port_prefers_instance_hostname():
    n = _dual_host_gw_node()
    assert X._gw_hostname_for_port(n, 3305) == "app05.example"


def test_gw_hostname_for_port_single_host_fallback_to_node_hostname():
    """Single-host nodes (the overwhelming common case) must still get
    node.hostname — this preserves the pre-PR-B long_lu behaviour."""
    n = SAPNode(sid="T", ip="10.0.0.1", hostname="single.example")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={3300: "gateway"})]
    # inst.hostname is empty — fall through to node.hostname.
    assert X._gw_hostname_for_port(n, 3300) == "single.example"


def test_gw_hostname_for_port_falls_through_to_inst_ip_then_node_ip():
    n = SAPNode(sid="T", ip="10.0.0.9", hostname="")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.9",
                                 ports={3300: "gateway"})]
    # node.hostname and inst.hostname both empty — inst.ip wins.
    assert X._gw_hostname_for_port(n, 3300) == "10.0.0.9"

    n2 = SAPNode(sid="T", ip="10.0.0.9", hostname="")
    n2.instances = [InstanceInfo(instance_nr="00", ip="",
                                  ports={3300: "gateway"})]
    # Empty everywhere except node.ip — node.ip is the last resort.
    assert X._gw_hostname_for_port(n2, 3300) == "10.0.0.9"


def test_gw_hostname_for_port_multihost_sparse_hostname_prefers_inst_ip():
    """Adversarial-review regression — the first PR-B cut had precedence
    ``inst.hostname → node.hostname → inst.ip → node.ip``, which on a
    multi-host node whose owning gateway instance has inst.ip set but
    NO inst.hostname (every autopwn / manual-add / legacy-state producer
    except the MS-import path) let node.hostname win and silently
    re-introduced the exact kernel-793 CPIC long_lu bug PR-B is meant
    to fix.  The owning instance's ip must beat node.hostname when it
    identifies a DIFFERENT box than node.ip."""
    n = SAPNode(sid="T", ip="10.0.0.1", hostname="ms.example")
    n.instances = [
        InstanceInfo(instance_nr="00", ip="10.0.0.1", ports={3601: "sapms"}),
        InstanceInfo(instance_nr="05", ip="10.0.0.5", hostname="",
                     ports={3305: "gateway"}),
    ]
    # NOT "ms.example" — that's the central-services hostname (wrong box).
    # The owning instance identifies 10.0.0.5 and has no hostname, so its
    # IP is the least-wrong long_lu we can produce.
    assert X._gw_hostname_for_port(n, 3305) == "10.0.0.5"


def test_gw_hostname_for_port_multihost_with_inst_hostname_still_wins():
    """When the owning instance DOES have inst.hostname, that remains the
    best answer — stays ahead of inst.ip in the precedence."""
    n = SAPNode(sid="T", ip="10.0.0.1", hostname="ms.example")
    n.instances = [InstanceInfo(instance_nr="05", ip="10.0.0.5",
                                 hostname="app05.example",
                                 ports={3305: "gateway"})]
    assert X._gw_hostname_for_port(n, 3305) == "app05.example"


def test_gw_hostname_for_port_single_host_inst_ip_equals_node_ip_uses_node_hostname():
    """Guard the single-host regression explicitly: when inst.ip ==
    node.ip (common single-host state), node.hostname wins — the
    adversarial-review refinement must NOT prefer inst.ip there."""
    n = SAPNode(sid="T", ip="10.0.0.1", hostname="single.example")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={3300: "gateway"})]
    assert X._gw_hostname_for_port(n, 3300) == "single.example"


def test_gw_hostname_for_port_unknown_port_returns_node_level():
    """Legacy / hand-edited state that doesn't match any instance falls
    back to node.hostname (so the pre-PR-B behaviour remains for callers
    that pass a port no instance claims)."""
    n = SAPNode(sid="T", ip="10.0.0.1", hostname="legacy.example")
    n.instances = [InstanceInfo(instance_nr="00", ip="10.0.0.1",
                                 ports={3601: "sapms"})]
    assert X._gw_hostname_for_port(n, 9999) == "legacy.example"


def test_gw_instance_nr_for_port():
    n = _dual_host_gw_node()
    assert X._gw_instance_nr_for_port(n, 3305) == "05"
    assert X._gw_instance_nr_for_port(n, 9999) == ""


# ---------------------------------------------------------------------------
# Source pins — every target_hostname source in the exploit module now
# flows from _gw_hostname_for_port (not node.hostname), and the DB-writer
# calls thread the owning hostname through.
# ---------------------------------------------------------------------------

def _exploit_src() -> str:
    with open(_EXPLOIT_SRC_PATH) as f:
        return f.read()


def _func_body(func_name: str) -> str:
    src = _exploit_src()
    tree = ast.parse(src, filename=_EXPLOIT_SRC_PATH)
    for node in ast.walk(tree):
        if (isinstance(node, ast.FunctionDef)
                and node.name == func_name):
            return ast.get_source_segment(src, node)
    raise AssertionError(f"{func_name} not found")


def test_probe_gw_port_for_xpg_hostname_from_helper():
    body = _func_body("_probe_gw_port_for_xpg")
    # The hostname variable that feeds build_p2(target_hostname=hostname)
    # must come from _gw_hostname_for_port, not a bare node.hostname.
    assert "_gw_hostname_for_port(node, gw_port)" in body, (
        "_probe_gw_port_for_xpg must resolve target_hostname via "
        "_gw_hostname_for_port (issue #255 part 3, kernel-793)")


def test_execute_gw_command_hostname_from_helper():
    body = _func_body("execute_gw_command")
    assert "_gw_hostname_for_port(node, gw_port)" in body, (
        "execute_gw_command must resolve target_hostname via "
        "_gw_hostname_for_port (issue #255 part 3, kernel-793)")


def test_create_user_gw_exploit_db_writers_get_owning_hostname():
    """The three DB-writer calls (_oracle_write_and_exec_win,
    _mssql_write_and_exec_win, _execute_sql_via_gateway) inside
    create_user_gw_exploit used to pass ``node.hostname or host`` as
    their hostname arg; after PR-B they pass the owning-instance
    hostname (gw_target_hostname computed from _gw_hostname_for_port)."""
    body = _func_body("create_user_gw_exploit")
    assert "gw_target_hostname" in body, (
        "create_user_gw_exploit must compute gw_target_hostname via "
        "_gw_hostname_for_port and pass it into each DB writer")
    assert "_gw_hostname_for_port(node, gw_port)" in body, (
        "create_user_gw_exploit's gw_target_hostname must be sourced "
        "from _gw_hostname_for_port, not node.hostname alone")
    # Pin the 3 call sites consume the new variable.
    assert body.count("gw_target_hostname,") >= 3, (
        "All three DB writers (Oracle/MSSQL/Sybase-default) must "
        "receive gw_target_hostname as their 4th positional arg")


# ---------------------------------------------------------------------------
# Multi-host end-to-end: a dual-host MS+PAS node goes through P2 with the
# PAS instance's hostname as target_hostname, NOT the MS one.
# ---------------------------------------------------------------------------

def test_execute_gw_command_passes_owning_hostname_to_build_p2(monkeypatch):
    """Integration regression — monkeypatch build_p2 to capture its
    target_hostname kwarg and prove execute_gw_command now passes the
    gateway instance's own hostname (app05.example), NOT the central-
    services hostname (ms.example)."""
    import sapmap_exploit as X

    captured = {}

    def _fake_build_p2(target_ip, dest_name="T_75", local_ip=None,
                       target_hostname=None):
        captured["target_hostname"] = target_hostname
        # Return a bytes-ish sentinel so the next step tries to send it.
        return b"P2"

    # Only the P2 build + socket interactions need stubbing — short-
    # circuit the whole chain after P2 so we don't need a real socket.
    monkeypatch.setattr(X, "build_p2", _fake_build_p2)

    class _FakeSock:
        def __init__(self): self.closed = False
        def settimeout(self, t): pass
        def connect(self, addr): pass
        def sendall(self, b): pass
        def recv(self, n): return b""
        def getsockname(self): return ("127.0.0.1", 0)
        def close(self): self.closed = True

    monkeypatch.setattr(X, "_gw_connect",
                        lambda h, p, r="", timeout=20: _FakeSock())

    # Stub ni_send / ni_recv / ni_drain / parse_response / build_p1 so
    # the chain gets to the P2 build call then exits via an error branch.
    monkeypatch.setattr(X, "ni_send", lambda s, b: None)
    monkeypatch.setattr(X, "ni_recv", lambda s, n: b"")
    monkeypatch.setattr(X, "ni_drain", lambda s, t: None)
    monkeypatch.setattr(X, "build_p1", lambda host, inst: b"P1")
    monkeypatch.setattr(X, "parse_response",
                        lambda b, stage: {"error": False, "conv_id": ""}
                        if stage == "P1" else {"error": True,
                                               "error_msg": "stop"})
    # Make GW_EXPLOIT_AVAILABLE truthy.
    monkeypatch.setattr(X, "_GW_EXPLOIT_AVAILABLE", True)

    n = _dual_host_gw_node()
    n.gw_vulnerable_port = 3305
    X.execute_gw_command(n, "/bin/true")
    assert captured.get("target_hostname") == "app05.example", (
        f"execute_gw_command passed target_hostname="
        f"{captured.get('target_hostname')!r} — expected "
        f"'app05.example' (owning-instance hostname), NOT the central-"
        f"services hostname 'ms.example'")


# ---------------------------------------------------------------------------
# Signature pins — make a drift that strips the 4-tuple fail loudly.
# ---------------------------------------------------------------------------

def _func_arg_count(func_name: str) -> int:
    src = _exploit_src()
    tree = ast.parse(src, filename=_EXPLOIT_SRC_PATH)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            return len(node.args.args)
    raise AssertionError(f"{func_name} not found")


def test_find_gw_endpoint_single_arg():
    assert _func_arg_count("_find_gw_endpoint") == 1


def test_find_gw_port_single_arg():
    # #246's contract — still exactly one positional arg.
    assert _func_arg_count("_find_gw_port") == 1


def test_find_gw_endpoint_present_in_source():
    src = _exploit_src()
    assert "def _find_gw_endpoint" in src
    assert "def _gw_hostname_for_port" in src
    assert "def _gw_instance_nr_for_port" in src
