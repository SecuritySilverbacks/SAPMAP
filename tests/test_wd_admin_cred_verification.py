"""Tests for issue #63 — the WD admin default-credential probe must not
report creds as valid on a generic non-401 response.

`probe_wd_admin_credentials` used `live = (status > 0 and status != 401)`, so
when `/sap/wdisp/admin` is unreachable and the listener rewrites the request to
a static 2xx page (no 401 Basic-auth gate anywhere), SAPMAP raised a CRITICAL
"WD admin default credentials LIVE" finding even though nothing authenticated.

The fix is tiered (`_wd_cred_verdict`):
  * behind a real 401 auth-gate, a 401 -> non-401 transition is trusted ("gated");
  * with NO 401 gate (ambiguous), a non-401 is trusted only when the body has
    genuine WD-admin content markers AND differs from the unauthenticated
    response ("content"); otherwise the attempt is "ambiguous_unconfirmed" and
    NOT live.

Harness: monkeypatch the module's `_http_get` seam with a responder that returns
one response for unauthenticated probes (no auth_header) and another for
authenticated probes (auth_header set) — mirrors tests/test_cve_2022_22536.py.
"""
from __future__ import annotations

import pytest

import modules  # noqa: F401 — registers package paths

import sap_wdisp_admin as W


_OK = b"HTTP/1.0 200 OK\r\n"
_UNAUTH = b"HTTP/1.0 401 Unauthorized\r\n" \
          b'WWW-Authenticate: Basic realm="WEB ADMIN"\r\n'
_STATIC = b"<html><body>Access not allowed</body></html>"
_ADMIN = b"wdisp/system_0 = SID=GSM, MSHOST=sapgsm, MSPORT=8121, SSL_ENCRYPT=2"


def _responder(unauth, authed):
    """_http_get replacement: returns `unauth` for pre-flight probes (no
    auth_header) and `authed` for credentialed probes."""
    def _get(host, port, path, *, https, timeout, auth_header="", saprouter=""):
        return authed if auth_header else unauth
    return _get


def _probe(monkeypatch, unauth, authed, creds=(("webadm", "webadm"),)):
    monkeypatch.setattr(W, "_http_get", _responder(unauth, authed))
    return W.probe_wd_admin_credentials(
        "wd.example", 8080, https=False, timeout=1,
        creds=list(creds), verbose=False)


# ===========================================================================
# _body_has_wd_admin_markers
# ===========================================================================

@pytest.mark.parametrize("body,expected", [
    (b"", False),
    (b"<html>Access denied</html>", False),
    (b"<html><title>login</title></html>", False),
    # loose / spoofable markers are NO LONGER trusted (issue #63 review r2):
    (b'{"url":"/api/v1/status","name":"config","config":true,"system":1}', False),
    (b"<html>contact the MSHOST admin team on MSPORT 3600</html>", False),
    # request-path reflection in a non-WD JSON error body must NOT match
    (b'{"error":"forbidden","url":"/sap/wdisp/admin/"}', False),
    # a nav JSON merely pointing at an .icp endpoint is no longer sufficient
    (b'{"name":"Parameters","url":"/sap/wdisp/admin/icp/parameter.icp"}', False),
    # genuine, unspoofable WD markers
    (b"wdisp/system_0 = SID=GSM, MSHOST=sapgsm, MSPORT=8121, SSL_ENCRYPT=2", True),
    (b"<tr><td>wdisp/system_1</td><td>SID=PRD</td></tr>", True),
    (b"webadm:{SHA256}abc123==", True),
])
def test_body_markers(body, expected):
    assert W._body_has_wd_admin_markers(body) is expected


# ===========================================================================
# _wd_cred_verdict — the tiered decision
# ===========================================================================

@pytest.mark.parametrize("status,body,status0,body0,ambiguous,exp", [
    # gated: a real 401 auth-gate existed → a 2xx/3xx is trusted
    (200, b"x", 401, b"", False, (True, "gated")),
    (302, b"", 401, b"", False, (True, "gated")),
    (401, b"", 401, b"", False, (False, "rejected")),
    # a 4xx other than 401 (behind a gate) is NOT a success (issue #63 r2)
    (403, b"x", 401, b"", False, (False, "rejected")),
    (0,   b"", 401, b"", False, (False, "unreachable")),
    # ambiguous (no gate): non-401 alone proves nothing (issue #63)
    (200, _STATIC, 200, _STATIC, True, (False, "ambiguous_unconfirmed")),
    # ambiguous + admin markers the unauth response lacked → trusted
    (200, _ADMIN, 200, _STATIC, True, (True, "content")),
    # ambiguous + markers already present unauthenticated (anonymous) → not live
    (200, _ADMIN, 200, _ADMIN, True, (False, "ambiguous_unconfirmed")),
    # ambiguous + a per-request nonce makes the body differ but adds NO admin
    # markers → must stay NOT live (a raw body-diff would be fooled here)
    (200, _STATIC + b"<!-- req=abc123 ts=9 -->", 200, _STATIC, True,
     (False, "ambiguous_unconfirmed")),
    # ambiguous + 403 authed, even with admin markers in the error body →
    # rejected (a 4xx never reaches the content check)
    (403, _ADMIN, 200, _STATIC, True, (False, "rejected")),
])
def test_verdict(status, body, status0, body0, ambiguous, exp):
    assert W._wd_cred_verdict(status, body, status0, body0, ambiguous) == exp


# ===========================================================================
# probe_wd_admin_credentials — end-to-end through the HTTP seam
# ===========================================================================

def test_issue63_static_2xx_rewrite_is_not_live(monkeypatch):
    """The exact issue: no path 401s; every GET returns the same static 2xx
    'not allowed' page → creds must NOT be reported live."""
    live, working, attempts, _ = _probe(
        monkeypatch, (200, _OK, _STATIC), (200, _OK, _STATIC))
    assert live is False
    assert working is None
    assert attempts[-1]["confidence"] == "ambiguous_unconfirmed"


def test_ambiguous_with_admin_content_is_live(monkeypatch):
    """No 401 gate, but the authed response returns the real backend table
    (markers) and differs from the static unauth page → live via content."""
    live, working, attempts, _ = _probe(
        monkeypatch, (200, _OK, _STATIC), (200, _OK, _ADMIN))
    assert live is True
    assert working == ("webadm", "webadm")
    assert attempts[-1]["confidence"] == "content"


def test_ambiguous_anonymous_content_is_not_live(monkeypatch):
    """Admin content served identically with and without creds (anonymous) →
    the credential proved nothing, so not live."""
    live, _working, attempts, _ = _probe(
        monkeypatch, (200, _OK, _ADMIN), (200, _OK, _ADMIN))
    assert live is False
    assert attempts[-1]["confidence"] == "ambiguous_unconfirmed"


def test_gated_401_then_200_is_live(monkeypatch):
    """Regression: a real 401 auth-gate followed by a 200 with creds stays a
    confirmed login (the reliable path must not be weakened)."""
    live, working, attempts, _ = _probe(
        monkeypatch, (401, _UNAUTH, b""), (200, _OK, b"<spa/>"))
    assert live is True
    assert working == ("webadm", "webadm")
    assert attempts[-1]["confidence"] == "gated"


def test_gated_401_then_401_is_rejected(monkeypatch):
    """A 401 gate that still 401s with creds → genuine rejection."""
    live, working, attempts, _ = _probe(
        monkeypatch, (401, _UNAUTH, b""), (401, _UNAUTH, b""))
    assert live is False
    assert working is None
    assert attempts[-1]["confidence"] == "rejected"


def test_reflection_403_is_not_live(monkeypatch):
    """issue #63 review r2: a non-WD gateway that 403-rejects Basic creds and
    echoes the requested /sap/wdisp/admin path in a JSON error body must NOT be
    reported live (neither the path-echo marker nor the 4xx status counts)."""
    live, working, attempts, _ = _probe(
        monkeypatch,
        (200, _OK, b"<html>portal landing</html>"),          # unauth anon page
        (403, b"HTTP/1.0 403 Forbidden\r\n",
         b'{"error":"forbidden","url":"/sap/wdisp/admin/"}'))  # reject + echo
    assert live is False
    assert working is None
    assert attempts[-1]["confidence"] == "rejected"


# ===========================================================================
# Caller B result-handling (_record_wd_default_probe_result) — behavioural:
# a confirmed login raises CRITICAL + stores a verified cred; an
# ambiguous_unconfirmed probe gets a LOW note and stores NOTHING.
# ===========================================================================

def _wd_node(sid="WDX"):
    from sapmap_models import SAPNode
    return SAPNode(sid=sid, ip="10.0.0.5")


def _attempt(confidence, status=200, live=False):
    return {"user": "webadm", "live": live, "status": status,
            "realm": "", "https": False,
            "verify_path": "/sap/wdisp/admin/", "confidence": confidence}


def test_confirmed_live_raises_critical_and_stores_verified_cred():
    import sapmap_gui
    from sapmap_models import Severity
    node = _wd_node()
    ret = sapmap_gui._record_wd_default_probe_result(
        node, "WDX", 44300, True, True, ("webadm", "webadm"),
        [_attempt("gated", 200, live=True)])
    assert ret == ("webadm", "webadm")
    assert node.has_critical_finding is True
    wd = [c for c in node.credentials if getattr(c, "kind", "") == "wd_admin"]
    assert len(wd) == 1 and wd[0].verified is True and wd[0].password == "webadm"
    assert any(f.severity == Severity.CRITICAL for f in node.findings)


def test_ambiguous_unconfirmed_low_note_no_cred_no_critical():
    """The #63 invariant on the caller side: no CRITICAL, no stored credential,
    exactly one low-severity note."""
    import sapmap_gui
    from sapmap_models import Severity
    node = _wd_node()
    ret = sapmap_gui._record_wd_default_probe_result(
        node, "WDX", 8080, False, False, None,
        [_attempt("ambiguous_unconfirmed", 200)])
    assert ret is None
    assert node.has_critical_finding is False
    assert [c for c in node.credentials
            if getattr(c, "kind", "") == "wd_admin"] == []
    lows = [f for f in node.findings if f.severity == Severity.LOW]
    assert len(lows) == 1
    assert not any(f.severity == Severity.CRITICAL for f in node.findings)


def test_plain_rejected_records_nothing():
    import sapmap_gui
    node = _wd_node()
    ret = sapmap_gui._record_wd_default_probe_result(
        node, "WDX", 44300, True, False, None,
        [_attempt("rejected", 401)])
    assert ret is None
    assert node.findings == []
    assert node.has_critical_finding is False
    assert node.credentials == []
