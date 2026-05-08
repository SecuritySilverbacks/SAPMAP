#!/usr/bin/env python3
"""P3 backfill tests:

  * sapmap_copyfail.is_kernel_vulnerable      — pure function
  * sapmap_copyfail.check_copyfail            — early-exit branches
  * sapmap_scc_fingerprint.scc_fingerprint    — probe ladder logic
  * sapmap_rfc.execute_local_command          — dest reuse / host alias matching

All offline; pyrfc and HTTP/TLS are stubbed.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


# ===========================================================================
# 1. sapmap_copyfail.is_kernel_vulnerable
# ===========================================================================

@pytest.mark.parametrize("kernel,expected", [
    # Vulnerable: pre-7.x and below the patched 6.18.22 / 6.19.12 cutoffs
    ("6.4.0-150500.55.83-default", True),
    ("6.4.0", True),
    ("6.10.5-1-default",           True),
    ("6.18.0",                     True),
    ("6.18.21",                    True),
    ("6.19.0",                     True),
    ("6.19.11",                    True),
    # Patched:
    ("6.18.22",                    False),
    ("6.18.23",                    False),
    ("6.19.12",                    False),
    ("6.19.13-default",            False),
    # 7.x and above — unaffected (CopyFail bug fixed in mainline)
    ("7.0.0",                      False),
    ("7.1.5",                      False),
    ("8.2.1",                      False),
    # Garbage input
    ("",                           False),
    ("not-a-kernel",               False),
    ("only.numbers.here",          False),  # no actual digits group of three
])
def test_is_kernel_vulnerable(kernel, expected):
    from sapmap_copyfail import is_kernel_vulnerable
    assert is_kernel_vulnerable(kernel) is expected


# ===========================================================================
# 2. sapmap_copyfail.check_copyfail — early-exit branches
# ===========================================================================

def _node(os_type="Linux"):
    from sapmap_models import SAPNode
    return SAPNode(sid="ORA", ip="10.0.0.1", hostname="orahost",
                   system_type="ABAP", os_type=os_type)


def test_check_copyfail_windows_short_circuits():
    """Windows hosts must early-exit with reason set, no exec_gw calls."""
    from sapmap_copyfail import check_copyfail
    with patch("sapmap_exploit.execute_gw_command") as mock_exec:
        out = check_copyfail(_node(os_type="Windows Server 2019"))
    assert out["vulnerable"] is False
    assert "Windows" in out["reason"]
    mock_exec.assert_not_called()


def test_check_copyfail_unreadable_kernel():
    """If `uname -r` returns nothing parseable, exit with the right reason."""
    from sapmap_copyfail import check_copyfail
    with patch("sapmap_exploit.execute_gw_command",
               return_value={"output": [""]}):
        out = check_copyfail(_node())
    assert out["vulnerable"] is False
    assert "Could not read kernel" in out["reason"]


def test_check_copyfail_patched_kernel_skips_authencesn():
    """When the kernel is patched, we must NOT proceed to the AF_ALG bind
    step — that's only valuable on actually-vulnerable kernels."""
    from sapmap_copyfail import check_copyfail
    call_log = []

    def fake_exec(node, prog, params, long_params=""):
        call_log.append((prog, params))
        if prog == "uname":
            return {"output": ["6.18.22-default"]}  # patched
        # Should never get here for AF_ALG
        return {"output": [""]}

    with patch("sapmap_exploit.execute_gw_command", side_effect=fake_exec):
        out = check_copyfail(_node())

    assert out["vulnerable"] is False
    assert "patched version" in out["reason"]
    # uname was the only command run
    assert len(call_log) == 1
    assert call_log[0][0] == "uname"


# ===========================================================================
# 3. sapmap_scc_fingerprint.scc_fingerprint — probe ladder
# ===========================================================================

def _tls_reachable():
    return {"reachable": True, "subject": "CN=test-scc",
            "issuer": "CN=ca", "alpn": "http/1.1"}


def test_scc_fingerprint_no_tls_returns_none():
    """If TLS handshake fails the probe must return None instead of a
    misleading is_scc=False object."""
    import sapmap_scc_fingerprint as fp
    with patch.object(fp, "_tls_fingerprint",
                      return_value={"reachable": False}):
        out = fp.scc_fingerprint("10.0.0.99", 8443, timeout=1.0)
    assert out is None


def test_scc_fingerprint_redirect_to_scc_ui_marks_scc():
    """A 302 → /scc/ui from `/` is the canonical SCC indicator and must
    set is_scc=True even if no HTML markers come through."""
    import sapmap_scc_fingerprint as fp

    def fake_http_get(host, port, path, timeout):
        if path == "/":
            return (302, {"Location": "/scc/ui",
                          "Server": "Apache-Coyote/1.1"}, b"")
        # /scc/ui: empty SPA shell, no markers
        return (200, {"Set-Cookie": "JSESSIONID=abc"}, b"<html></html>")

    with patch.object(fp, "_tls_fingerprint", return_value=_tls_reachable()), \
         patch.object(fp, "_http_get", side_effect=fake_http_get), \
         patch.object(fp, "_favicon_hashes", return_value=("", 0)):
        out = fp.scc_fingerprint("10.0.0.1", 8443, timeout=1.0)

    assert out is not None
    assert out["is_scc"] is True
    assert out["redirect_to_scc_ui"] is True


def test_scc_fingerprint_html_marker_marks_scc():
    """Even without a redirect, a known title/HTML marker is enough."""
    import sapmap_scc_fingerprint as fp

    body = (b"<html><head><title>SAP Cloud Connector</title></head>"
            b"<body><script src='/scc/ui/main.abc123def456.js'></script>"
            b"</body></html>")

    def fake_http_get(host, port, path, timeout):
        if path == "/":
            return (200, {}, b"<html></html>")
        return (200, {"Server": "SAP Cloud Connector",
                      "Set-Cookie": "JSESSIONID=xyz"}, body)

    with patch.object(fp, "_tls_fingerprint", return_value=_tls_reachable()), \
         patch.object(fp, "_http_get", side_effect=fake_http_get), \
         patch.object(fp, "_favicon_hashes", return_value=("deadbeef", 42)):
        out = fp.scc_fingerprint("10.0.0.2", 8443, timeout=1.0)

    assert out is not None and out["is_scc"] is True
    assert out["title_present"] is True
    assert out["server_header"] == "SAP Cloud Connector"
    assert out["favicon_sha256"] == "deadbeef"
    assert out["favicon_mmh3"] == 42


def test_scc_fingerprint_returns_none_when_clearly_not_scc():
    """Random web-server with no SCC indicators must return None so the
    scanner doesn't tag the host as a Cloud Connector."""
    import sapmap_scc_fingerprint as fp

    def fake_http_get(host, port, path, timeout):
        return (200, {"Server": "nginx/1.21"}, b"<html><body>hi</body></html>")

    with patch.object(fp, "_tls_fingerprint", return_value=_tls_reachable()), \
         patch.object(fp, "_http_get", side_effect=fake_http_get):
        out = fp.scc_fingerprint("10.0.0.3", 443, timeout=1.0)
    assert out is None


def test_scc_fingerprint_version_from_api_endpoint():
    """If `/api/monitoring/versions` returns 200 + JSON with a version,
    promote that to the canonical version field."""
    import sapmap_scc_fingerprint as fp

    api_body = b'{"connector":"2.16.2","build":"abc"}'

    def fake_http_get(host, port, path, timeout):
        if path == "/":
            return (302, {"Location": "/scc/ui"}, b"")
        if path == "/scc/ui":
            return (200, {"Set-Cookie": "JSESSIONID=q"},
                    b"<html><title>SAP Cloud Connector</title></html>")
        if path == "/api/monitoring/versions":
            return (200, {}, api_body)
        return (404, {}, b"")

    with patch.object(fp, "_tls_fingerprint", return_value=_tls_reachable()), \
         patch.object(fp, "_http_get", side_effect=fake_http_get), \
         patch.object(fp, "_favicon_hashes", return_value=("", 0)):
        out = fp.scc_fingerprint("10.0.0.4", 8443, timeout=1.0)

    assert out is not None and out["is_scc"] is True
    assert out["version"] == "2.16.2"
    assert out["version_source"] == "api"


# ===========================================================================
# 4. execute_local_command — dest reuse / host alias matching
# ===========================================================================

class _FakeConn:
    """Stub pyrfc connection that returns canned RFC_READ_TABLE rows."""
    def __init__(self, rfcdes_rows):
        self._rows = rfcdes_rows

    def call(self, fm, **kwargs):
        if fm == "RFC_READ_TABLE" and kwargs.get("QUERY_TABLE") == "RFCDES":
            # Each RFCDES "WA" string is RFCDEST|RFCTYPE|RFCOPTIONS
            return {"DATA": [{"WA": wa} for wa in self._rows]}
        # Should not be called for anything else in these tests
        raise RuntimeError(f"unexpected RFC call: {fm}")


class _FakeCtx:
    def __init__(self, conn):
        self._conn = conn
    def __enter__(self):
        return self._conn
    def __exit__(self, *a):
        return False


def _node_with_hostname(ip="10.0.0.5", hostname="orahost.corp.example.com"):
    from sapmap_models import SAPNode, InstanceInfo
    n = SAPNode(sid="ORA", ip=ip, hostname=hostname, system_type="ABAP")
    n.instances.append(InstanceInfo(instance_nr="00", ip=ip,
                                     ports={3300: "gateway"}))
    return n


def _creds():
    from sapmap_models import Credentials
    return Credentials(username="SAPMAP00", password="x", client="001",
                       instance_nr="00")


def test_execute_local_command_reuses_existing_loopback_dest():
    """A sapxpg dest pointing at LOCALHOST must be reused — no
    create_tcpip_destination call, just go straight to remote_command."""
    import sapmap_rfc

    conn = _FakeConn(rfcdes_rows=[
        "OLD_LOOP_DEST|T|PROGRAM=SAPXPG GWHOST=LOCALHOST GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx) as gc, \
         patch.object(sapmap_rfc, "create_tcpip_destination") as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": ["x"], "error": ""}) as run:
        out = sapmap_rfc.execute_local_command(
            _node_with_hostname(), "uname", "-r", _creds()
        )

    mk_dest.assert_not_called()
    run.assert_called_once()
    # The reused dest name must be passed to execute_remote_command
    assert run.call_args.args[1] == "OLD_LOOP_DEST"
    assert out["success"] is True


def test_execute_local_command_reuses_dest_matching_node_ip():
    """A sapxpg dest pointing at the node's IP (not localhost) must also
    be reused."""
    import sapmap_rfc

    conn = _FakeConn(rfcdes_rows=[
        # Garbage entry — wrong host, should be skipped
        "OTHER|T|PROGRAM=SAPXPG GWHOST=192.168.99.99 GWSERV=3300",
        # Match — exact IP
        "MY_DEST|T|PROGRAM=SAPXPG GWHOST=10.0.0.5 GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx), \
         patch.object(sapmap_rfc, "create_tcpip_destination") as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [], "error": ""}) as run:
        sapmap_rfc.execute_local_command(
            _node_with_hostname(ip="10.0.0.5"), "ls", "/tmp", _creds()
        )

    mk_dest.assert_not_called()
    assert run.call_args.args[1] == "MY_DEST"


def test_execute_local_command_reuses_dest_matching_short_hostname():
    """Hostnames in RFCOPTIONS are often the short form (no FQDN);
    matcher must accept short-name aliases of node.hostname."""
    import sapmap_rfc

    conn = _FakeConn(rfcdes_rows=[
        "DEST_BY_SHORT|T|PROGRAM=SAPXPG GWHOST=ORAHOST GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx), \
         patch.object(sapmap_rfc, "create_tcpip_destination") as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [], "error": ""}) as run:
        sapmap_rfc.execute_local_command(
            _node_with_hostname(hostname="orahost.corp.example.com"),
            "ls", "/tmp", _creds()
        )

    mk_dest.assert_not_called()
    assert run.call_args.args[1] == "DEST_BY_SHORT"


def test_execute_local_command_creates_new_dest_when_no_match():
    """When no existing sapxpg dest matches the host, the function must
    fall back to create_tcpip_destination()."""
    import sapmap_rfc

    # No matching rows
    conn = _FakeConn(rfcdes_rows=[
        "UNRELATED|T|PROGRAM=SAPXPG GWHOST=192.168.50.50 GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx), \
         patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value={"success": True,
                                    "dest_name": "SAPMAP_NEW_DEST",
                                    "message": "ok"}) as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [], "error": ""}) as run:
        sapmap_rfc.execute_local_command(
            _node_with_hostname(ip="10.0.0.5"),
            "id", "", _creds()
        )

    mk_dest.assert_called_once()
    # The newly-created dest must be the one passed onwards
    assert run.call_args.args[1] == "SAPMAP_NEW_DEST"


def test_execute_local_command_skips_sapmap_dests_for_other_sids():
    """Regression: the dest-reuse loop must NEVER pick up a SAPMAP-named
    destination created for a DIFFERENT SID, even if its RFCOPTIONS
    happens to share a substring with the local node's host alias.
    Otherwise SXPG silently sends commands to the wrong system and the
    download_password_hashes flow hangs/errors with no useful log."""
    import sapmap_rfc

    conn = _FakeConn(rfcdes_rows=[
        # SAPMAP destination for a DIFFERENT SID — must be skipped even
        # though its options happen to mention LOCALHOST/127.0.0.1.
        "SAPMAP_W74_20260305165242|T|PROGRAM=SAPXPG GWHOST=127.0.0.1 GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx), \
         patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value={"success": True,
                                    "dest_name": "SAPMAP_S4H_FRESH",
                                    "message": "ok"}) as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [], "error": ""}) as run:
        from sapmap_models import SAPNode, InstanceInfo
        node = SAPNode(sid="S4H", ip="10.0.0.5",
                       hostname="s4hhost.corp.example.com",
                       system_type="ABAP")
        node.instances.append(InstanceInfo(instance_nr="00", ip="10.0.0.5",
                                            ports={3300: "gateway"}))
        sapmap_rfc.execute_local_command(node, "id", "", _creds())

    # Must NOT reuse the W74-named dest; must create a fresh one.
    mk_dest.assert_called_once()
    assert run.call_args.args[1] == "SAPMAP_S4H_FRESH"


def test_execute_local_command_prefers_sapmap_dest_for_own_sid():
    """When both a SAPMAP_<own-sid>_* dest AND a generic localhost dest
    exist, the SAPMAP-prefixed one for THIS node wins — it's the highest-
    confidence match (we created it ourselves, for this exact node)."""
    import sapmap_rfc

    conn = _FakeConn(rfcdes_rows=[
        # Generic operator-created dest matching by host alias
        "OLD_LOOP|T|PROGRAM=SAPXPG GWHOST=LOCALHOST GWSERV=3300",
        # Our own SAPMAP-created dest for this SID — should win
        "SAPMAP_S4H_20260101000000|T|PROGRAM=SAPXPG GWHOST=10.0.0.5 GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx), \
         patch.object(sapmap_rfc, "create_tcpip_destination") as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [], "error": ""}) as run:
        from sapmap_models import SAPNode, InstanceInfo
        node = SAPNode(sid="S4H", ip="10.0.0.5", hostname="s4hhost",
                       system_type="ABAP")
        node.instances.append(InstanceInfo(instance_nr="00", ip="10.0.0.5",
                                            ports={3300: "gateway"}))
        sapmap_rfc.execute_local_command(node, "id", "", _creds())

    mk_dest.assert_not_called()
    assert run.call_args.args[1] == "SAPMAP_S4H_20260101000000"


def test_execute_local_command_skips_non_sapxpg_dests():
    """Type-T destinations that are NOT sapxpg (e.g. registered programs
    for external RFC servers) must not be matched even if the host string
    happens to align."""
    import sapmap_rfc

    conn = _FakeConn(rfcdes_rows=[
        # Registered RFC server — same host but NOT sapxpg
        "EXT_REG|T|PROGRAM=PYRFC_SERVER GWHOST=10.0.0.5 GWSERV=3300",
    ])
    ctx = _FakeCtx(conn)

    with patch.object(sapmap_rfc, "_get_connection", return_value=ctx), \
         patch.object(sapmap_rfc, "create_tcpip_destination",
                      return_value={"success": True,
                                    "dest_name": "FRESH_DEST",
                                    "message": "ok"}) as mk_dest, \
         patch.object(sapmap_rfc, "execute_remote_command",
                      return_value={"success": True, "output": [], "error": ""}) as run:
        sapmap_rfc.execute_local_command(
            _node_with_hostname(ip="10.0.0.5"),
            "id", "", _creds()
        )

    # Non-sapxpg matches must be ignored, so create_tcpip_destination runs
    mk_dest.assert_called_once()
    assert run.call_args.args[1] == "FRESH_DEST"
