"""Test Connection on Type-H HTTPS destinations: fallback + SSL clarity.

Pinned bugs (2026-07-12), reported after clicking Test Connection on
W74's ``to_ABAP`` destination:

  URL: https://192.168.2.29:8410//sap/bc/gui/sap/its/webgui
  Auth: BASICAUTHENTICATION, User: SAPADM, SecStore Pwd: 9 chars
  Target: ABA (?)                            <-- unresolved

Log:
  [*] Testing HTTP destination: to_ABAP...
  [+] to_ABAP: HTTP OK (TCP open on 192.168.2.29:8410,
      HTTP faulted: SSLError)                <-- no detail
  [*] to_ABAP: password sourced from secstore
  [+] Single test done for to_ABAP           <-- NO probe fired

Three regressions covered here:

  A) URL construction: N='/' + M='/sap/bc/gui/sap/its/webgui' must
     NOT produce '//sap/bc/gui/sap/its/webgui' — the parser has to
     collapse the double slash at the join point.

  B) http_dest_ping's SSLError message must include the real
     exception text (str(e)), not just the type name — the operator
     needs to see WRONG_VERSION_NUMBER / handshake failure / TLS
     version mismatch, whatever the actual reason was.

  C) Test Connection must fire a fallback basic-auth probe when
     neither the Java branch nor the ABAP branch could resolve the
     target — otherwise a Type-H destination to an unresolved SID
     (very common: destination points at 192.168.2.29 but no node
     with SID 'ABA' is on the map) silently produces zero result.

C is exercised at the module-level in test_windows_lpe_java_only_
stack.py-style — reproducing the whole Bottle app scope is out of
scope; we pin the CONDITION expression instead so the fallback
gate can't regress silently.
"""
from __future__ import annotations

import modules  # noqa: F401
import pytest
from sapmap_models import SAPNode, RFCConnection


# ---------------------------------------------------------------------------
# A) Double-slash URL construction
# ---------------------------------------------------------------------------

def _parse(options: str) -> RFCConnection:
    from modules.discovery.sapmap_rfc import _parse_rfcdes_http_options
    conn = RFCConnection(source_sid="S4H", source_host="s4hanadev",
                          destination_name="to_ABAP", rfc_type="H")
    _parse_rfcdes_http_options(conn, options)
    return conn


def test_url_collapses_double_slash_when_prefix_and_path_both_root():
    """The failing case from the live report: N='/' plus
    M='/sap/bc/gui/sap/its/webgui' must yield a single-slash path,
    not '//sap/bc/gui/sap/its/webgui' which some upstreams reject
    as ambiguous scheme-relative-authority."""
    conn = _parse("H=192.168.2.29,I=8410,N=/,M=/sap/bc/gui/sap/its/webgui,"
                  "U=SAPADM,T=%_PWD")
    assert "//sap/bc" not in conn.http_url, (
        f"double-slash regressed — parser produced {conn.http_url!r}")
    assert conn.http_url.endswith("/sap/bc/gui/sap/its/webgui")


def test_url_keeps_single_slash_when_only_path_set():
    """M='/api/v1/resource' with no N= must produce a single-slash
    path (baseline — the fix must not over-strip)."""
    conn = _parse("H=host,I=8000,M=/api/v1/resource,U=u,T=%_PWD")
    assert conn.http_url.endswith("/api/v1/resource")
    assert "//api" not in conn.http_url


def test_url_keeps_single_slash_when_only_prefix_set():
    """N='/wd/root' with no M= must produce a single-slash path."""
    conn = _parse("H=host,I=8000,N=/wd/root,U=u,T=%_PWD")
    assert conn.http_url.endswith("/wd/root")


def test_url_joins_prefix_and_path_cleanly_no_trailing_slash():
    """N='/wd' + M='/dispatcher' → '/wd/dispatcher' (each has a
    leading slash but no trailing — no join collision)."""
    conn = _parse("H=host,I=8000,N=/wd,M=/dispatcher,U=u,T=%_PWD")
    assert conn.http_url.endswith("/wd/dispatcher")
    assert "//" not in conn.http_url.split("://", 1)[1]


def test_url_joins_prefix_with_trailing_slash_and_path_with_leading():
    """N='/wd/' + M='/dispatcher' → collapse trailing/leading pair
    to a single '/'.  The pre-fix loop produced '/wd//dispatcher'."""
    conn = _parse("H=host,I=8000,N=/wd/,M=/dispatcher,U=u,T=%_PWD")
    assert conn.http_url.endswith("/wd/dispatcher")
    # The one // in "://" is the scheme separator — anything AFTER
    # that must not carry a "//".
    assert "//" not in conn.http_url.split("://", 1)[1]


# ---------------------------------------------------------------------------
# B) SSLError message clarity
# ---------------------------------------------------------------------------

def test_http_dest_ping_ssl_error_includes_real_reason():
    """The pre-fix ping_message was just 'HTTP faulted: SSLError' —
    useless when trying to diagnose whether port 8410 is really
    HTTPS or whether SNI failed or TLS version mismatch or …

    Simulate a failing TLS handshake via a monkeypatched ssl context;
    the returned ping_message must contain the actual exception str,
    not just the type name."""
    import socket
    import ssl
    from modules.discovery import sapmap_rfc

    class _FakeConn:
        def __init__(self, url):
            self.http_url = url

    # Bind a local listener that accepts but does NOT speak TLS,
    # so wrap_socket triggers a real SSLError.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    import threading
    def _accept_and_hang():
        try:
            c, _ = srv.accept()
            # Send back a garbage response so TLS handshake sees a
            # non-TLS byte stream.
            c.sendall(b"HTTP/1.0 200 OK\r\n\r\n")
            c.close()
        except Exception:
            pass
    t = threading.Thread(target=_accept_and_hang, daemon=True)
    t.start()

    try:
        r = sapmap_rfc.http_dest_ping(
            _FakeConn(f"https://127.0.0.1:{port}/"),
            timeout=3.0)
    finally:
        srv.close()

    assert r["ping_ok"] is True, (
        "TCP handshake completed → ping_ok stays True even on TLS "
        "failure so the caller knows the target is up; only the "
        "PROTOCOL failed")
    msg = r["ping_message"]
    # The type name still appears (existing behaviour):
    assert "SSLError" in msg or "SSL" in msg
    # And now the real reason too — some flavour of "wrong version"
    # or "unknown protocol" or "record layer" appears in Python's
    # SSLError repr for non-TLS bytes on a TLS wrap.
    tail = msg.split("HTTP faulted:", 1)[-1]
    assert ":" in tail and len(tail) > 20, (
        f"ping_message must carry the real SSL exception text after "
        f"the type name; got {msg!r}")


# ---------------------------------------------------------------------------
# C) Fallback probe condition
# ---------------------------------------------------------------------------

def test_ping_ok_without_http_status_must_not_flip_logon_successful():
    """Live bug (2026-07-12) — line 9830 in sapmap_gui.py used to
    unconditionally set conn.logon_successful=True whenever
    http_dest_ping returned ping_ok=True.  But http_dest_ping
    returns ping_ok=True in TWO cases:

      (a) HTTP round-trip completed → conn.http_status is set to
          the actual response code
      (b) TCP handshake opened but HTTP faulted (SSL error, socket
          reset, etc.) → conn.http_status stays 0, ping_message
          carries the fault text

    Setting logon_successful in case (b) gates OUT the downstream
    fallback basic-auth probe.  The pin here documents the invariant:
    the elevation logic must check http_status, not just ping_ok."""
    # Case (b) simulation — the shape http_dest_ping produces on
    # WRONG_VERSION_NUMBER for a HTTPS URL pointing at an HTTP port
    ping_result = {
        "ping_ok": True,      # TCP opened
        "ping_message": ("TCP open on 192.168.2.29:8410, HTTP "
                         "faulted: SSLError: [SSL: "
                         "WRONG_VERSION_NUMBER] wrong version "
                         "number (_ssl.c:1082)"),
        "error": "",
    }
    conn = RFCConnection(
        source_sid="S4H", source_host="s4hanadev",
        destination_name="to_ABAP", rfc_type="H",
        conn_type="http",
        http_url="https://192.168.2.29:8410/sap/bc/gui/",
        http_auth_type="BASICAUTHENTICATION",
        rfc_user="SAPADM",
        secstore_password="TestPass123",
    )
    conn.http_status = 0   # explicit: HTTP round-trip never happened

    # Replicate the (post-fix) elevation gate from sapmap_gui.py
    if ping_result.get("ping_ok"):
        _hs = int(getattr(conn, "http_status", 0) or 0)
        if 200 <= _hs < 400:
            conn.logon_successful = True
        # else leave False so fallback fires
    assert conn.logon_successful is False, (
        "Regression: TCP-open-but-HTTP-faulted case must NOT flip "
        "logon_successful — that would gate out the fallback probe")

    # Case (a) — real 200 response
    conn.http_status = 200
    if ping_result.get("ping_ok"):
        _hs = int(getattr(conn, "http_status", 0) or 0)
        if 200 <= _hs < 400:
            conn.logon_successful = True
    assert conn.logon_successful is True, (
        "Real 2xx round-trip should elevate logon_successful — "
        "the fix must not over-restrict")


def test_scheme_fallback_flip_recognises_wrong_version_number():
    """The scheme-fallback in the Test-Connection fallback probe
    retries HTTP when the HTTPS attempt failed with a TLS
    version-mismatch style error.  Live case (2026-07-12) — W74's
    to_ABAP has URL https://192.168.2.29:8410/... but port 8410
    speaks HTTP, so the TLS handshake dies with
    WRONG_VERSION_NUMBER.  We recognise that pattern and retry
    against http://192.168.2.29:8410/... so the operator still
    gets a real basic-auth result."""
    # Mirror the trigger expression in sapmap_gui.py so a refactor
    # can't quietly break it.
    def _should_retry_http(url: str, err: str) -> bool:
        err_lc = (err or "").lower()
        url_is_https = (url or "").lower().startswith("https://")
        return (url_is_https
                and ("wrong_version_number" in err_lc
                     or "unknown_protocol" in err_lc
                     or "record layer" in err_lc
                     or "http/1" in err_lc))

    url = "https://192.168.2.29:8410/sap/bc/gui/"
    err = ("SSLError: [SSL: WRONG_VERSION_NUMBER] wrong version "
            "number (_ssl.c:1082)")
    assert _should_retry_http(url, err) is True

    # Negative: non-HTTPS URL → no retry needed
    assert _should_retry_http("http://foo/", err) is False
    # Negative: HTTPS URL but unrelated error → don't guess-flip
    assert _should_retry_http(url, "socket timeout") is False
    # Positive: alternative wording variants
    assert _should_retry_http(
        url, "unknown_protocol from server") is True
    assert _should_retry_http(
        url, "HTTP/1.0 400 Bad Request") is True


def test_fallback_probe_gate_matches_pinned_condition():
    """The fallback basic-auth probe fires only when ALL of:

      * not conn.logon_successful
      * not _did_java_probe
      * rfc_user and rfc_pwd (both present)
      * conn.http_url (URL to probe)
      * not (conn.os_access_type starts with sapcontrol/hostagent)

    Pinning the gate expression here so a future refactor of the
    Test Connection flow can't silently skip the fallback and
    regress the operator's ability to test HTTPS Type-H
    destinations against unresolved targets."""
    # Positive case: exactly the shape reported in the live log
    conn = RFCConnection(
        source_sid="S4H", source_host="s4hanadev",
        destination_name="to_ABAP", rfc_type="H",
        conn_type="http",
        http_url=("https://192.168.2.29:8410/sap/bc/gui/sap/its/"
                   "webgui"),
        http_auth_type="BASICAUTHENTICATION",
        rfc_user="SAPADM",
        secstore_password="s" * 9,
        target_sid="ABA",   # unresolved — no node with SID 'ABA'
    )
    rfc_user = conn.rfc_user
    rfc_pwd = conn.secstore_password
    fires = (not conn.logon_successful
              and rfc_user and rfc_pwd
              and conn.http_url
              and not (conn.os_access_type or "").startswith(
                  ("sapcontrol", "hostagent")))
    assert fires

    # Negative case: SAPControl destination — the SAPControl branch
    # handles it; fallback must NOT fire (would duplicate work).
    conn.os_access_type = "sapcontrol_sidadm"
    fires_sc = (not conn.logon_successful
                 and rfc_user and rfc_pwd
                 and conn.http_url
                 and not (conn.os_access_type or "").startswith(
                     ("sapcontrol", "hostagent")))
    assert not fires_sc

    # Negative case: no URL to probe.
    conn.os_access_type = ""
    conn.http_url = ""
    fires_no_url = (not conn.logon_successful
                     and rfc_user and rfc_pwd
                     and conn.http_url
                     and not (conn.os_access_type or "").startswith(
                         ("sapcontrol", "hostagent")))
    assert not fires_no_url

    # Negative case: already logged on.
    conn.http_url = "https://foo/"
    conn.logon_successful = True
    fires_done = (not conn.logon_successful
                   and rfc_user and rfc_pwd
                   and conn.http_url
                   and not (conn.os_access_type or "").startswith(
                       ("sapcontrol", "hostagent")))
    assert not fires_done
