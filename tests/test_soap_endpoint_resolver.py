"""Tests for _resolve_soap_endpoint — picks the right host:port for a
SOAP-RFC call against a Type-G/H connection's target node.

The resolver has a three-step priority chain (node ports → URL port →
probe).  These tests lock each step's contract independently so a
regression in one path doesn't fall through unnoticed to the next.
"""
from __future__ import annotations

import modules  # noqa: F401  registers package paths
import sapmap_gui
from sapmap_gui import _resolve_soap_endpoint
from sapmap_models import InstanceInfo, RFCConnection, SAPNode


def _make_target_node(sid="W74", ports=None):
    inst = InstanceInfo(
        instance_nr="40",
        ip="192.168.2.29",
        ports=dict(ports or {}),
    )
    return SAPNode(
        sid=sid, system_type="ABAP",
        hostname="WINWAS74", ip="192.168.2.29",
        instances=[inst],
    )


def _make_http_conn(http_url=""):
    return RFCConnection(
        source_sid="S4H", source_host="s4hanadev",
        destination_name="to_ABAP", conn_type="http",
        http_url=http_url, rfc_user="SAPADM",
    )


# ---------------------------------------------------------------------------
# Step 1: prefer the node's persisted icm-http(s) port over anything else
# ---------------------------------------------------------------------------

def test_resolver_uses_node_icm_http_port_when_present():
    """If a prior probe already found an ICM HTTP port and recorded it
    on the node, the resolver must use that — no re-probing, no falling
    through to the URL port (which is often the wrong :80 default)."""
    node = _make_target_node(
        ports={3240: "dispatcher", 3340: "gateway", 8410: "icm-http"})
    conn = _make_http_conn(http_url="http://192.168.2.29/sap/bc/rfc")
    out = _resolve_soap_endpoint(conn, node)
    assert out["ok"] is True
    assert out["host"] == "192.168.2.29"
    assert out["port"] == 8410
    assert out["https"] is False


def test_resolver_uses_node_icm_https_port_when_present():
    """When the persisted port is labelled icm-https, https flag flips."""
    node = _make_target_node(
        ports={3240: "dispatcher", 8443: "icm-https"})
    conn = _make_http_conn(http_url="http://192.168.2.29/whatever")
    out = _resolve_soap_endpoint(conn, node)
    assert out["ok"] is True
    assert out["port"] == 8443
    assert out["https"] is True


# ---------------------------------------------------------------------------
# Step 2: fall back to conn.http_url when it carries a non-default port
# ---------------------------------------------------------------------------

def test_resolver_uses_url_port_when_node_has_no_icm_port():
    """If conn.http_url has an explicit non-default port (e.g. :8410),
    use it directly — no need to probe."""
    node = _make_target_node(
        ports={3240: "dispatcher", 3340: "gateway"})
    conn = _make_http_conn(
        http_url="http://192.168.2.29:8410/sap/bc/srt/rfc")
    out = _resolve_soap_endpoint(conn, node)
    assert out["ok"] is True
    assert out["host"] == "192.168.2.29"
    assert out["port"] == 8410


def test_resolver_skips_default_url_port_and_falls_through():
    """conn.http_url with port 80 (or no explicit port) is almost always
    the result of RFCDES parser stripping a default — DO NOT trust it.
    Without a node icm-http port and without successful probing, the
    resolver must report failure rather than blindly returning :80."""
    node = _make_target_node(
        ports={3240: "dispatcher", 3340: "gateway"})
    # Avoid the live probe by pointing at an unroutable address
    conn = _make_http_conn(http_url="http://10.255.255.1/sap/bc/srt/rfc")
    out = _resolve_soap_endpoint(conn, node)
    # Step 3 (probe) will fail against 10.255.255.1 — so resolver
    # must surface failure, not return port 80
    assert out["ok"] is False or out["port"] != 80


# ---------------------------------------------------------------------------
# Step 3: probe falls through when nothing else works
# ---------------------------------------------------------------------------

def test_resolver_calls_probe_and_persists_port_on_node(monkeypatch):
    """When step 1 and step 2 fail, the resolver invokes
    _discover_sid_http and persists the discovered ICM port on the node
    so subsequent calls hit step 1 immediately."""
    fake_info = {
        "sid": "W74", "instance_nr": "40",
        "hostname": "WINWAS74", "ip": "192.168.2.29",
        "icm_port": 8410, "icm_scheme": "http",
    }
    calls = []

    def _fake_discover(base):
        calls.append(base)
        return dict(fake_info)

    monkeypatch.setattr(sapmap_gui, "_discover_sid_http", _fake_discover)

    node = _make_target_node(
        ports={3240: "dispatcher", 3340: "gateway"})
    conn = _make_http_conn(http_url="http://192.168.2.29/")
    out = _resolve_soap_endpoint(conn, node)

    assert out["ok"] is True
    assert out["port"] == 8410
    assert calls == ["http://192.168.2.29"]
    # Node now carries icm-http=8410 so the next call short-circuits
    assert 8410 in node.instances[0].ports
    assert node.instances[0].ports[8410] == "icm-http"


def test_resolver_reports_error_when_no_http_url(monkeypatch):
    """If neither node ports nor http_url provide an endpoint, and we
    have no URL to probe with, fail cleanly (not crash)."""
    # Don't actually call the probe — assert resolver reports failure
    # without it being invoked, since there's no URL to probe against.
    monkeypatch.setattr(
        sapmap_gui, "_discover_sid_http",
        lambda *_a, **_k: (_ for _ in ()).throw(
            AssertionError("probe must not be called when no URL")),
    )
    node = _make_target_node(ports={3240: "dispatcher"})
    conn = _make_http_conn(http_url="")
    out = _resolve_soap_endpoint(conn, node)
    assert out["ok"] is False
    assert "no ICM port" in out["error"].lower() or out["error"]
