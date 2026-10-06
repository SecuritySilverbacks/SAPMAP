"""Tests for the NAT-aware MS probe + 10KBLAZE attacker-IP override.

Covers:
  * probe_ms_apparent_ip() shape + candidate filtering + sections tried
  * subnet_mismatch() boolean heuristic
  * SAPNode.attacker_ip_override + attacker_ip_force field roundtrip
  * sap_betrusted_chain.try_betrusted_chain reads the per-node override
    and triggers the NAT warning when subnets differ
  * sap_ms_betrusted.betrusted force_attacker_ip wiring (static pin)
  * sapmap_gui /api/node/<sid>/set_attacker_ip + get_attacker_ip route
    pins
  * HTML ctx-menu entry + modal + dispatcher JS pin
"""
from __future__ import annotations

import pathlib
import re

import pytest

import modules  # noqa: F401 — path registration


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# subnet_mismatch — boolean heuristic
# ---------------------------------------------------------------------------

def test_subnet_mismatch_fires_on_different_slash24():
    from sap_ms_info_disclosure import subnet_mismatch
    assert subnet_mismatch("192.168.68.104", "192.168.2.209") is True
    assert subnet_mismatch("10.0.0.5",        "192.168.2.209") is True


def test_subnet_mismatch_quiet_on_same_slash24():
    from sap_ms_info_disclosure import subnet_mismatch
    assert subnet_mismatch("192.168.2.196",  "192.168.2.209") is False
    assert subnet_mismatch("192.168.2.1",    "192.168.2.254") is False


def test_subnet_mismatch_tolerant_of_bad_input():
    from sap_ms_info_disclosure import subnet_mismatch
    assert subnet_mismatch("", "192.168.2.1") is False
    assert subnet_mismatch("not-ip", "192.168.2.1") is False
    assert subnet_mismatch("1.2.3", "1.2.3.4") is False
    assert subnet_mismatch(None, "1.2.3.4") is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# probe_ms_apparent_ip — unit (mocked _http_get)
# ---------------------------------------------------------------------------

def test_probe_ms_apparent_ip_mines_server_addr_from_params(monkeypatch):
    """When MS_DUMP_PARAMS returns a body, the probe must extract the
    ``server addr`` value regardless of what CON/CLIENTS/DOMAIN_CONN
    return."""
    import sap_ms_info_disclosure as mod
    params_body = (
        b"dump : MS_DUMP_PARAMS\n"
        b"Release = 793\n"
        b"server host = s4hanadev\n"
        b"server addr = 192.168.2.209\n"
        b"ms/conn_timeout = 300\n"
    )

    def _fake_get(host, port, path, timeout, saprouter=""):
        if "?3=1" in path:
            return (200, params_body, "")
        # Empty connection tables — same shape as live NW 7.5x+ / 7.9x.
        return (200, b"dump : MS_DUMP_CON\n", "")

    monkeypatch.setattr(mod, "_http_get", _fake_get)
    r = mod.probe_ms_apparent_ip("192.168.2.209", inst_nr=1, timeout=1.0)
    assert r["ok"] is True
    assert r["server_addr"] == "192.168.2.209"
    assert r["candidate_ips"] == []
    assert r["best_apparent_ip"] == ""
    # Every section was tried.
    sections = [s[0] for s in r["sections_tried"]]
    assert set(sections) == {3, 2, 4, 7}


def test_probe_ms_apparent_ip_extracts_single_snat_candidate(monkeypatch):
    """When a CON table (old kernel) carries a dotted-quad that isn't
    the server's own addr or loopback, it becomes the best apparent
    IP candidate."""
    import sap_ms_info_disclosure as mod

    def _fake_get(host, port, path, timeout, saprouter=""):
        if "?3=1" in path:
            return (200,
                    b"dump : MS_DUMP_PARAMS\nserver addr = 192.168.2.209\n",
                    "")
        if "?2=1" in path:
            # Pretend an old kernel exposed a connection record with
            # the apparent client IP.
            return (200,
                    b"dump : MS_DUMP_CON\n"
                    b"con slot 0: 192.168.2.1 port 48512\n",
                    "")
        return (200, b"dump : MS_DUMP_EMPTY\n", "")

    monkeypatch.setattr(mod, "_http_get", _fake_get)
    r = mod.probe_ms_apparent_ip("192.168.2.209", inst_nr=1, timeout=1.0)
    assert r["best_apparent_ip"] == "192.168.2.1"
    assert "192.168.2.1" in r["candidate_ips"]
    # Server addr + loopback filtered out.
    assert "192.168.2.209" not in r["candidate_ips"]


def test_probe_ms_apparent_ip_filters_loopback_and_server_addr(monkeypatch):
    import sap_ms_info_disclosure as mod

    def _fake_get(host, port, path, timeout, saprouter=""):
        if "?3=1" in path:
            return (200, b"dump : MS_DUMP_PARAMS\nserver addr = 10.0.0.5\n", "")
        return (200,
                b"dump : MS_DUMP_CON\n"
                b"row 127.0.0.1 row 10.0.0.5 row 0.0.0.0 "
                b"row 127.0.0.17 row 255.255.255.255\n",
                "")

    monkeypatch.setattr(mod, "_http_get", _fake_get)
    r = mod.probe_ms_apparent_ip("10.0.0.5", inst_nr=1, timeout=1.0)
    # Every candidate above is either the server addr, loopback, or
    # the broadcast placeholder — all must be filtered.
    assert r["candidate_ips"] == []


def test_probe_ms_apparent_ip_reports_error_on_no_data(monkeypatch):
    import sap_ms_info_disclosure as mod

    def _fake_get(host, port, path, timeout, saprouter=""):
        return (0, b"", "TimeoutError: timed out")

    monkeypatch.setattr(mod, "_http_get", _fake_get)
    r = mod.probe_ms_apparent_ip("192.168.2.150", inst_nr=1, timeout=1.0)
    assert r["ok"] is False
    assert r["server_addr"] == ""
    assert r["candidate_ips"] == []
    assert "no usable data" in r["error"]


def test_probe_ms_apparent_ip_rejects_non_dump_bodies(monkeypatch):
    """A 200 response that doesn't carry the MS_DUMP banner (e.g. an
    HTML error page from an ACL-protected proxy) must be treated as
    'no data', not parsed."""
    import sap_ms_info_disclosure as mod

    def _fake_get(host, port, path, timeout, saprouter=""):
        return (200,
                b"<html><body>192.168.2.1 192.168.2.42</body></html>",
                "")

    monkeypatch.setattr(mod, "_http_get", _fake_get)
    r = mod.probe_ms_apparent_ip("192.168.2.1", inst_nr=1, timeout=1.0)
    assert r["candidate_ips"] == []
    assert r["server_addr"] == ""


# ---------------------------------------------------------------------------
# SAPNode.attacker_ip_override + attacker_ip_force roundtrip
# ---------------------------------------------------------------------------

def test_sapnode_attacker_ip_override_roundtrips():
    from sapmap_models import SAPNode
    n = SAPNode(sid="S4H",
                 attacker_ip_override="192.168.2.42",
                 attacker_ip_force=True)
    d = n.to_dict()
    assert d["attacker_ip_override"] == "192.168.2.42"
    assert d["attacker_ip_force"] is True
    restored = SAPNode.from_dict(d)
    assert restored.attacker_ip_override == "192.168.2.42"
    assert restored.attacker_ip_force is True


def test_sapnode_attacker_ip_fields_default_empty():
    from sapmap_models import SAPNode
    n = SAPNode(sid="S4H")
    assert n.attacker_ip_override == ""
    assert n.attacker_ip_force is False
    d = n.to_dict()
    assert d["attacker_ip_override"] == ""
    assert d["attacker_ip_force"] is False


# ---------------------------------------------------------------------------
# try_betrusted_chain — static source pins (behavioural + plumbing)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def chain_src() -> str:
    return (REPO_ROOT / "modules" / "exploitation"
            / "sap_betrusted_chain.py").read_text(encoding="utf-8")


def test_chain_accepts_force_attacker_ip_kwarg(chain_src: str):
    assert "force_attacker_ip: bool = False" in chain_src


def test_chain_reads_node_attacker_ip_override_before_auto_detect(
        chain_src: str):
    """The per-node persistent override must win over the kernel
    routing-table auto-detect but lose to a caller-supplied kwarg."""
    assert 'getattr(node, "attacker_ip_override", "")' in chain_src
    assert 'getattr(node, "attacker_ip_force", False)' in chain_src


def test_chain_fires_subnet_mismatch_warning(chain_src: str):
    """When auto-detected attacker_ip is on a different /24, LOG a
    loud warning + emit a bus finding BEFORE launching betrusted."""
    assert "subnet_mismatch(" in chain_src
    assert "NAT WARNING" in chain_src
    assert "exploit.10kblaze.nat_warning" in chain_src


def test_chain_plumbs_force_attacker_ip_into_betrusted_call(chain_src: str):
    """try_betrusted_chain must pass force_attacker_ip through to the
    worker thread, otherwise the auto-swap at sap_ms_betrusted.py
    overwrites the operator's value."""
    assert "force_attacker_ip=force_attacker_ip" in chain_src


def test_chain_force_flag_suppresses_subnet_warning(chain_src: str):
    """When the operator has explicitly forced an IP (reverse-tunnel /
    bastion setup), the chain should NOT emit the NAT warning — the
    operator already knows what they're doing."""
    # The warning is gated on `not force_attacker_ip`.
    m = re.search(r"if subnet_mismatch is not None and not force_attacker_ip",
                   chain_src)
    assert m, "subnet_mismatch warning must be gated on `not force_attacker_ip`"


# ---------------------------------------------------------------------------
# /api/node/<sid>/set_attacker_ip + get_attacker_ip route pins
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gui_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_gui.py").read_text(
        encoding="utf-8")


def test_set_attacker_ip_route_registered(gui_src: str):
    assert ('@app.route("/api/node/<sid>/set_attacker_ip", method="POST")'
            in gui_src)
    assert "def node_set_attacker_ip(sid):" in gui_src


def test_get_attacker_ip_route_registered(gui_src: str):
    assert '@app.route("/api/node/<sid>/get_attacker_ip")' in gui_src
    assert "def node_get_attacker_ip(sid):" in gui_src


def test_set_attacker_ip_in_write_routes(gui_src: str):
    """POST is destructive (persists on node); must be refused in
    --read-only mode."""
    m = re.search(r"WRITE_ROUTES = frozenset\(\{(.*?)\}\)",
                   gui_src, re.DOTALL)
    assert m
    assert '"/api/node/<sid>/set_attacker_ip"' in m.group(1)


def test_set_attacker_ip_route_persists_both_fields(gui_src: str):
    idx = gui_src.find(
        '@app.route("/api/node/<sid>/set_attacker_ip", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert "node.attacker_ip_override = raw_ip" in body
    assert "node.attacker_ip_force = force if raw_ip else False" in body


def test_set_attacker_ip_route_validates_ipv4_shape(gui_src: str):
    idx = gui_src.find(
        '@app.route("/api/node/<sid>/set_attacker_ip", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert '"error": "bad_attacker_ip"' in body
    assert "0 <= int(p) <= 255" in body


def test_set_attacker_ip_route_warns_on_subnet_mismatch(gui_src: str):
    """When operator sets an IP that's STILL on a different /24 from
    the target, the save succeeds but a warning fires so they can
    double-check."""
    idx = gui_src.find(
        '@app.route("/api/node/<sid>/set_attacker_ip", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert "subnet_mismatch(raw_ip, host)" in body


def test_set_attacker_ip_route_returns_404_on_missing_node(gui_src: str):
    idx = gui_src.find(
        '@app.route("/api/node/<sid>/set_attacker_ip", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert "response.status = 404" in body


def test_betrusted_route_accepts_force_attacker_ip(gui_src: str):
    """/api/node/<sid>/betrusted body must honour {force_attacker_ip:
    true} so an operator-specified IP isn't silently swapped at the
    sap_ms_betrusted.py level."""
    idx = gui_src.find('@app.route("/api/node/<sid>/betrusted", method="POST")')
    end = gui_src.find('@app.route(', idx + 1)
    body = gui_src[idx:end]
    assert 'data.get("force_attacker_ip"' in body
    assert "force_attacker_ip=force_attacker_ip" in body


# ---------------------------------------------------------------------------
# Frontend ctx-menu + modal pins
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def html_src() -> str:
    return (REPO_ROOT / "modules" / "core" / "sapmap_html.py").read_text(
        encoding="utf-8")


def test_ctx_menu_entry_present_in_exploitation_submenu(html_src: str):
    assert 'data-action="set_attacker_ip"' in html_src
    assert "Set 10KBLAZE Attacker IP" in html_src


def test_ctx_menu_entry_carries_write_op_class(html_src: str):
    """Persisting on the node is a write-op; must hide under
    --read-only."""
    m = re.search(
        r'<div class="([^"]+)" data-action="set_attacker_ip"', html_src)
    assert m, "set_attacker_ip entry not found"
    classes = m.group(1).split()
    assert "write-op" in classes


def test_ctx_action_dispatches_to_modal(html_src: str):
    assert "case 'set_attacker_ip':" in html_src
    assert "showSetAttackerIpModal(sid)" in html_src


def test_modal_dom_anchor_present(html_src: str):
    assert 'id="set-attacker-ip-modal"' in html_src
    assert 'id="set-attacker-ip-value"' in html_src
    assert 'id="set-attacker-ip-force"' in html_src
    assert 'id="set-attacker-ip-warning"' in html_src


def test_modal_preloads_current_override_via_get(html_src: str):
    """showSetAttackerIpModal must GET the current override so the
    text field + force checkbox reflect what's already persisted."""
    assert "async function showSetAttackerIpModal(" in html_src
    assert "`node/${sid}/get_attacker_ip`" in html_src


def test_save_posts_both_fields(html_src: str):
    assert "async function saveSetAttackerIp(" in html_src
    assert "`node/${sid}/set_attacker_ip`" in html_src
    assert "force: force" in html_src


def test_save_leaves_modal_open_on_nat_warning(html_src: str):
    """When the backend returns nat_warning (operator picked an IP
    that's STILL subnet-mismatched), the modal shows the warning
    and does NOT close — operator can revise."""
    import re
    m = re.search(r"async function saveSetAttackerIp\(\).*?\n\}",
                   html_src, re.DOTALL)
    assert m
    body = m.group(0)
    assert "nat_warning" in body
    # Early return before closeModal when warning fires.
    assert body.find("w.style.display") < body.find("closeModal(")
