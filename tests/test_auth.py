#!/usr/bin/env python3
"""Tests for the optional server-side auth middleware (issue #40).

Hermetic: drives BasicAuthMiddleware directly over a fake WSGI app with a
fake verifier, so no PAM, no sockets, no python-pam needed.  The PAM backend
itself (PamVerifier) needs a live PAM/SSSD stack and is validated in the lab.
"""
from __future__ import annotations

import base64

import pytest

from sapmap_auth import (                      # noqa: E402
    BasicAuthMiddleware, StaticVerifier, protect,
)


def _basic(user, pwd):
    return "Basic " + base64.b64encode(
        ("%s:%s" % (user, pwd)).encode("utf-8")).decode("ascii")


def _app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def _call(mw, auth_header=None, path="/"):
    environ = {"PATH_INFO": path, "REQUEST_METHOD": "GET"}
    if auth_header is not None:
        environ["HTTP_AUTHORIZATION"] = auth_header
    out = {}

    def start_response(status, headers):
        out["status"] = status
        out["headers"] = dict(headers)

    body = mw(environ, start_response)
    out["body"] = b"".join(body)
    out["environ"] = environ
    return out


class _FakeVerifier:
    def __init__(self, accept=("alice", "pw")):
        self.accept = accept
        self.calls = 0

    def verify(self, user, pwd):
        self.calls += 1
        return user if (user, pwd) == self.accept else False


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

def test_static_verifier_constant_time_match():
    v = StaticVerifier("u", "p")
    assert v.verify("u", "p") == "u"
    assert v.verify("u", "x") is False
    assert v.verify("x", "p") is False


# ---------------------------------------------------------------------------
# Middleware — challenge / pass / reject
# ---------------------------------------------------------------------------

def test_no_header_challenges_401():
    r = _call(BasicAuthMiddleware(_app, _FakeVerifier()))
    assert r["status"].startswith("401")
    assert r["headers"].get("WWW-Authenticate", "").startswith("Basic realm=")


def test_malformed_header_challenges_not_crash():
    mw = BasicAuthMiddleware(_app, _FakeVerifier())
    for bad in ("Basic !!notbase64!!", "Bearer abc", "Basic", "garbage"):
        assert _call(mw, bad)["status"].startswith("401")


def test_valid_creds_pass_and_set_remote_user():
    r = _call(BasicAuthMiddleware(_app, _FakeVerifier()), _basic("alice", "pw"))
    assert r["status"].startswith("200")
    assert r["body"] == b"ok"
    assert r["environ"].get("REMOTE_USER") == "alice"


def test_wrong_password_challenges():
    r = _call(BasicAuthMiddleware(_app, _FakeVerifier()),
              _basic("alice", "nope"))
    assert r["status"].startswith("401")


# ---------------------------------------------------------------------------
# Cache + lockout
# ---------------------------------------------------------------------------

def test_cache_avoids_reverification():
    v = _FakeVerifier()
    mw = BasicAuthMiddleware(_app, v, cache_ttl=300)
    _call(mw, _basic("alice", "pw"))
    _call(mw, _basic("alice", "pw"))
    assert v.calls == 1, "second identical request should hit the cache"


def test_no_cache_when_ttl_zero():
    v = _FakeVerifier()
    mw = BasicAuthMiddleware(_app, v, cache_ttl=0)
    _call(mw, _basic("alice", "pw"))
    _call(mw, _basic("alice", "pw"))
    assert v.calls == 2


def test_local_lockout_trips_429():
    v = _FakeVerifier()
    mw = BasicAuthMiddleware(_app, v, max_failures=2, lockout_seconds=300)
    assert _call(mw, _basic("alice", "bad"))["status"].startswith("401")
    assert _call(mw, _basic("alice", "bad"))["status"].startswith("401")
    r = _call(mw, _basic("alice", "bad"))          # now locked out
    assert r["status"].startswith("429")
    assert "Retry-After" in r["headers"]
    # A locked-out user is rejected before the verifier is consulted again.
    assert v.calls == 2


# ---------------------------------------------------------------------------
# Excluded paths
# ---------------------------------------------------------------------------

def test_excluded_path_prefix_bypasses_auth():
    mw = BasicAuthMiddleware(_app, _FakeVerifier(), exclude=("/health",))
    r = _call(mw, path="/health/live")             # no Authorization header
    assert r["status"].startswith("200")
    # A non-excluded path still requires auth.
    assert _call(mw, path="/api/state")["status"].startswith("401")


# ---------------------------------------------------------------------------
# protect() wiring + disable bypass
# ---------------------------------------------------------------------------

def test_disable_env_returns_app_unwrapped(monkeypatch):
    monkeypatch.setenv("SAPMAP_AUTH_DISABLE", "1")
    assert protect(_app, announce=False) is _app


def test_protect_builds_static_backend(monkeypatch):
    monkeypatch.delenv("SAPMAP_AUTH_DISABLE", raising=False)
    monkeypatch.setenv("SAPMAP_AUTH_BACKEND", "static")
    monkeypatch.setenv("SAPMAP_USER", "bob")
    monkeypatch.setenv("SAPMAP_PASSWORD", "secret")
    wrapped = protect(_app, announce=False)
    assert isinstance(wrapped, BasicAuthMiddleware)
    ok = _call(wrapped, _basic("bob", "secret"))
    assert ok["status"].startswith("200")
    assert ok["environ"].get("REMOTE_USER") == "bob"
    assert _call(wrapped, _basic("bob", "wrong"))["status"].startswith("401")


def test_bad_backend_name_raises(monkeypatch):
    monkeypatch.delenv("SAPMAP_AUTH_DISABLE", raising=False)
    monkeypatch.setenv("SAPMAP_AUTH_BACKEND", "nonsense")
    with pytest.raises(RuntimeError):
        protect(_app, announce=False)
