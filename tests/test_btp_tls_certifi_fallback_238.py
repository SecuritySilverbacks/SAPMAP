"""Issue #238 — BTP TLS: shared certifi-backed context + opt-in insecure retry.

Background: the mint path used to blanket-disable TLS verification (CERT_NONE)
while the enumerate path (`_btp_get`) did full verification with no certifi
fallback, so on a stock python.org framework build (empty OpenSSL cert dir) the
mint always succeeded and the auto-enumerate always failed with

    [SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate

Design pinned by these tests (secure-by-default):
  * `btp_ssl_context()` verifies by default and grafts certifi's CA bundle
    ONLY when no explicit SSL_CERT_FILE/SSL_CERT_DIR store is configured
    (so an operator can still pin / narrow trust); `insecure=True` -> CERT_NONE.
  * `btp_is_cert_verify_error` matches ONLY certificate-VERIFICATION failures.
  * `_btp_get` and `mint_btp_token` verify first and FAIL CLOSED on a
    cert-verify error by default (they carry a Bearer token / client secret,
    so they never auto-downgrade on an attacker-triggerable signal).  The
    unverified retry happens only on an explicit `insecure=True` opt-in, and
    never for a generic network error or a non-cert TLS error.
"""
import io
import ssl
import sys
import urllib.error

import pytest

import sap_btp
from sap_onprem_to_btp import mint_btp_token


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

class _Resp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _cert_verify_urlerror():
    return urllib.error.URLError(
        ssl.SSLCertVerificationError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "unable to get local issuer certificate (_ssl.c:1147)"))


def _non_cvf_sslerror_urlerror():
    # A TLS handshake/protocol error that is NOT a certificate-verification
    # failure — must never trigger an insecure downgrade.
    return urllib.error.URLError(ssl.SSLError("WRONG_VERSION_NUMBER"))


def _httperror(url, code, body=b"{}"):
    return urllib.error.HTTPError(url, code, "err", {}, io.BytesIO(body))


def _empty_ctx(*a, **k):
    """A real but trust-store-EMPTY client context (0 CA certs), standing in
    for the stock-python framework build whose OpenSSL cert dir was never
    populated.  PROTOCOL_TLS_CLIENT defaults to CERT_REQUIRED + check_hostname.
    """
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


_UAA = "https://sub.authentication.eu10.hana.ondemand.com/oauth/token"


@pytest.fixture
def no_cert_env(monkeypatch):
    """Ensure no explicit CA store is configured, so the certifi graft runs."""
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


# --------------------------------------------------------------------------
# btp_ssl_context
# --------------------------------------------------------------------------

def test_btp_ssl_context_secure_defaults(no_cert_env):
    ctx = sap_btp.btp_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_btp_ssl_context_insecure():
    ctx = sap_btp.btp_ssl_context(insecure=True)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_graft_adds_certifi_roots_when_default_store_empty(monkeypatch,
                                                           no_cert_env):
    """Non-vacuous guard for the actual fix: start from a 0-cert context and
    prove the grafted anchors came from certifi, not the OS store."""
    try:
        import certifi  # noqa: F401
    except Exception:
        pytest.skip("certifi not installed")
    monkeypatch.setattr("sap_btp.ssl.create_default_context", _empty_ctx)
    assert len(sap_btp.btp_ssl_context().get_ca_certs()) > 0


def test_graft_skipped_when_SSL_CERT_FILE_set(monkeypatch):
    """Respect an operator's explicit trust store: do NOT graft certifi on
    top of SSL_CERT_FILE (which would silently widen a narrowed trust set)."""
    monkeypatch.setattr("sap_btp.ssl.create_default_context", _empty_ctx)
    monkeypatch.setenv("SSL_CERT_FILE", "/some/engagement-ca.pem")
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    # graft skipped -> the (empty) operator store is left exactly as-is
    assert sap_btp.btp_ssl_context().get_ca_certs() == []


def test_graft_skipped_when_SSL_CERT_DIR_set(monkeypatch):
    monkeypatch.setattr("sap_btp.ssl.create_default_context", _empty_ctx)
    monkeypatch.setenv("SSL_CERT_DIR", "/some/certs.d")
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    assert sap_btp.btp_ssl_context().get_ca_certs() == []


def test_context_survives_missing_certifi(monkeypatch, no_cert_env):
    """If certifi is absent, the helper must still return a verifying context
    (fail-closed), not crash."""
    monkeypatch.setattr("sap_btp.ssl.create_default_context", _empty_ctx)
    monkeypatch.setitem(sys.modules, "certifi", None)   # -> ImportError
    ctx = sap_btp.btp_ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


# --------------------------------------------------------------------------
# btp_is_cert_verify_error
# --------------------------------------------------------------------------

def test_predicate_true_for_cert_verify_error():
    assert sap_btp.btp_is_cert_verify_error(ssl.SSLCertVerificationError("x"))


def test_predicate_true_for_generic_sslerror_with_cvf_text():
    assert sap_btp.btp_is_cert_verify_error(
        ssl.SSLError("foo CERTIFICATE_VERIFY_FAILED bar"))


def test_predicate_false_for_other_sslerror():
    assert not sap_btp.btp_is_cert_verify_error(
        ssl.SSLError("WRONG_VERSION_NUMBER"))


@pytest.mark.parametrize("reason", [None, "a string",
                                     ConnectionRefusedError("refused"),
                                     ConnectionResetError(),
                                     TimeoutError()])
def test_predicate_false_for_non_cert_reasons(reason):
    assert not sap_btp.btp_is_cert_verify_error(reason)


# --------------------------------------------------------------------------
# _btp_get  (enumerate path — carries the Bearer token)
# --------------------------------------------------------------------------

def test_btp_get_verified_path_no_fallback(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        return _Resp(200, {"X": "1"}, b'{"ok":1}')

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    status, _h, body = sap_btp._btp_get("https://h/x", "tok",
                                         token_fp="t-verified")
    assert status == 200 and body == b'{"ok":1}'
    assert seen == [ssl.CERT_REQUIRED]


def test_btp_get_fail_closed_on_cert_verify_by_default(monkeypatch, capsys):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise _cert_verify_urlerror()

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    with pytest.raises(urllib.error.URLError):
        sap_btp._btp_get("https://h/x", "tok", token_fp="t-failclosed")
    assert seen == [ssl.CERT_REQUIRED]            # NO insecure downgrade
    out = capsys.readouterr().out
    assert "fail-closed" in out and "SSL_CERT_FILE" in out


def test_btp_get_insecure_optin_falls_back(monkeypatch, capsys):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        if context.verify_mode != ssl.CERT_NONE:
            raise _cert_verify_urlerror()
        return _Resp(200, {}, b'{"ok":1}')

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    status, _h, body = sap_btp._btp_get("https://h/x", "tok",
                                         token_fp="t-optin", insecure=True)
    assert status == 200 and body == b'{"ok":1}'
    assert seen == [ssl.CERT_REQUIRED, ssl.CERT_NONE]
    assert "UNVERIFIED" in capsys.readouterr().out


def test_btp_get_insecure_optin_retry_then_httperror(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        if context.verify_mode != ssl.CERT_NONE:
            raise _cert_verify_urlerror()
        raise _httperror("https://h/x", 403, b'{"e":1}')

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    status, _h, body = sap_btp._btp_get("https://h/x", "tok",
                                         token_fp="t-optin-http", insecure=True)
    assert status == 403 and body == b'{"e":1}'
    assert seen == [ssl.CERT_REQUIRED, ssl.CERT_NONE]


def test_btp_get_no_fallback_on_generic_urlerror(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise urllib.error.URLError(ConnectionRefusedError("refused"))

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    with pytest.raises(urllib.error.URLError):
        sap_btp._btp_get("https://h/x", "tok", token_fp="t-generic",
                         insecure=True)
    assert seen == [ssl.CERT_REQUIRED]


def test_btp_get_no_downgrade_on_non_cvf_sslerror(monkeypatch):
    """A handshake/protocol SSLError (possible MITM indicator) must NOT be
    downgraded, even with the insecure opt-in set."""
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise _non_cvf_sslerror_urlerror()

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    with pytest.raises(urllib.error.URLError):
        sap_btp._btp_get("https://h/x", "tok", token_fp="t-nonCVF",
                         insecure=True)
    assert seen == [ssl.CERT_REQUIRED]            # no CERT_NONE attempt


def test_btp_get_httperror_passthrough_no_fallback(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise _httperror("https://h/x", 403, b'{"err":1}')

    monkeypatch.setattr("sap_btp.urllib.request.urlopen", fake)
    status, _h, body = sap_btp._btp_get("https://h/x", "tok", token_fp="t-http")
    assert status == 403 and body == b'{"err":1}'
    assert seen == [ssl.CERT_REQUIRED]


# --------------------------------------------------------------------------
# mint_btp_token  (carries client_id/client_secret)
# --------------------------------------------------------------------------

def test_mint_verified_happy_path(monkeypatch, capsys):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        return _Resp(200, {}, b'{"access_token":"tok123"}')

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret")
    assert tok == "tok123" and err == ""
    assert seen == [ssl.CERT_REQUIRED]
    assert "UNVERIFIED" not in capsys.readouterr().out   # no downgrade notice


def test_mint_fail_closed_on_cert_verify_by_default(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise _cert_verify_urlerror()

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret")
    assert tok == ""
    assert "fail-closed" in err and "SSL_CERT_FILE" in err
    assert seen == [ssl.CERT_REQUIRED]            # NO insecure downgrade


def test_mint_insecure_optin_fallback(monkeypatch, capsys):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        if context.verify_mode != ssl.CERT_NONE:
            raise _cert_verify_urlerror()
        return _Resp(200, {}, b'{"access_token":"tok456"}')

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret", insecure=True)
    assert tok == "tok456" and err == ""
    assert seen == [ssl.CERT_REQUIRED, ssl.CERT_NONE]
    assert "UNVERIFIED" in capsys.readouterr().out


def test_mint_insecure_optin_retry_then_httperror(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        if context.verify_mode != ssl.CERT_NONE:
            raise _cert_verify_urlerror()
        raise _httperror(_UAA, 401, b'{"error":"invalid_client"}')

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret", insecure=True)
    assert tok == "" and err.startswith("HTTP 401")
    assert seen == [ssl.CERT_REQUIRED, ssl.CERT_NONE]


def test_mint_generic_urlerror_no_downgrade(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise urllib.error.URLError(ConnectionRefusedError("refused"))

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret", insecure=True)
    assert tok == "" and "unreachable" in err
    assert seen == [ssl.CERT_REQUIRED]


def test_mint_no_downgrade_on_non_cvf_sslerror(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise _non_cvf_sslerror_urlerror()

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret", insecure=True)
    assert tok == "" and "unreachable" in err
    assert seen == [ssl.CERT_REQUIRED]            # no CERT_NONE attempt


def test_mint_httperror_no_fallback(monkeypatch):
    seen = []

    def fake(req, timeout=None, context=None):
        seen.append(context.verify_mode)
        raise _httperror(_UAA, 401, b'{"error":"invalid_client"}')

    monkeypatch.setattr("sap_onprem_to_btp.urllib.request.urlopen", fake)
    tok, err = mint_btp_token(_UAA, "cid", "secret")
    assert tok == "" and err.startswith("HTTP 401")
    assert seen == [ssl.CERT_REQUIRED]
