"""
sapmap_auth.py — optional server-side authentication for SAPMAP's Bottle GUI.

Issue #40: when SAPMAP is served to others over the network (not the local
pywebview window), the HTTP GUI needs a gate.  This wraps the Bottle/WSGI app
in HTTP Basic auth, backed by Linux / Active-Directory accounts through PAM —
the "domain-joined access only" scenario — with a single-static-credential
fallback for non-domain use.

Design adapted from a reference implementation by Stijn (the PAM/SSSD verifier,
the AD-lockout-shielding local rate-limit, and the WSGI drop-in).

OFF BY DEFAULT.  SAPMAP wires this in only when the operator passes ``--auth``
(sapmap.py).  Without that flag the server runs exactly as before — no
middleware, no login — so existing local/pywebview usage is unchanged.

--------------------------------------------------------------------------
BACKENDS                          SAPMAP_AUTH_BACKEND = pam | static | auto
--------------------------------------------------------------------------
    pam     Authenticate against Linux/AD accounts through PAM (needs
            python-pam + libpam; the domain-joined path).
    static  Single username/password from SAPMAP_USER / SAPMAP_PASSWORD.
    auto    Use pam if importable, otherwise static (default).

--------------------------------------------------------------------------
WHO IS ALLOWED IN (pam backend)
--------------------------------------------------------------------------
Access is an explicit allowlist of logins — no AD group needed.  Set it via
SAPMAP_AUTH_USERS (comma-separated; "*" allows any account PAM accepts) or by
editing ALLOWED_USERS below.  An empty allowlist refuses to start rather than
silently expose every domain account.  The password itself is always verified
by AD through PAM — nothing here stores passwords.  Usernames are canonicalised
through NSS, and PAM's account phase enforces SSSD host-access control / expiry.

--------------------------------------------------------------------------
KEY ENV VARS (see README "Authentication" for the full list)
--------------------------------------------------------------------------
SAPMAP_AUTH_USERS        Comma-separated logins (replaces ALLOWED_USERS).
SAPMAP_AUTH_MAX_FAILURES Failed attempts per username before a LOCAL lockout.
                         Keep BELOW the AD lockout threshold so the local 429
                         trips first and shields the domain account.  Default 5.
SAPMAP_AUTH_LOCKOUT      Local lockout seconds.  Default 300.
SAPMAP_AUTH_CACHE_TTL    Seconds to cache a successful login.  Default 300.
SAPMAP_AUTH_EXCLUDE      Comma-separated URL path prefixes left open.
SAPMAP_AUTH_REALM        Browser prompt realm.  Default "SAPMAP".
SAPMAP_AUTH_PAM_SERVICE  PAM service name.  Default "sapmap" if
                         /etc/pam.d/sapmap exists, else "login".
SAPMAP_AUTH_DISABLE      Truthy → bypass auth entirely (even with --auth).
SAPMAP_AUTH_DEBUG        Truthy → log denial reasons + PAM codes.

WARNING: HTTP Basic sends credentials base64-encoded, not encrypted.  Put TLS
in front of the server or keep it on loopback / behind an SSH tunnel —
otherwise a domain password is readable on the network path, and a scanner
feeding failed logins into AD can lock out a colleague's account.
"""

import base64
import hmac
import os
import secrets
import sys
import threading
import time

__all__ = ["BasicAuthMiddleware", "protect", "run_protected",
           "PamVerifier", "StaticVerifier", "ALLOWED_USERS"]


# ===========================================================================
#  Domain or local logins allowed to reach the app, exactly as they appear in
#  `id` / `getent passwd`.  Matching is case-insensitive and CORP\name /
#  name@domain forms are accepted, so one bare entry per person is enough.
#  Empty by default: configure SAPMAP_AUTH_USERS, or add names here.
# ===========================================================================

ALLOWED_USERS = [
]

# ===========================================================================


_TRUTHY = ("1", "true", "yes", "on")


def _env_flag(name):
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _env_int(name, default):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def _env_list(name):
    """Split on commas only, so values may contain spaces."""
    raw = os.environ.get(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _log(message):
    print(message, file=sys.stdout, flush=True)


def _name_candidates(raw):
    """Ordered, de-duplicated login name variants to try against NSS."""
    seen = []
    forms = [raw]
    if "\\" in raw:
        forms.append(raw.rsplit("\\", 1)[-1])
    if "@" in raw:
        forms.append(raw.split("@", 1)[0])
    for form in forms:
        for candidate in (form, form.lower()):
            if candidate and candidate not in seen:
                seen.append(candidate)
    return seen


# ---------------------------------------------------------------------------
# Verifiers
#
# Contract: verify(username, password) returns the canonical username on
# success (a truthy string) or False on failure.
# ---------------------------------------------------------------------------

class StaticVerifier:
    """Single username/password pair (non-domain fallback)."""

    name = "static"

    def __init__(self, username, password):
        self._name = str(username)
        self._user = self._name.encode("utf-8")
        self._pass = str(password).encode("utf-8")

    def verify(self, username, password):
        user_ok = hmac.compare_digest(username.encode("utf-8"), self._user)
        pass_ok = hmac.compare_digest(password.encode("utf-8"), self._pass)
        return self._name if (user_ok and pass_ok) else False

    def describe(self):
        return "static single account '%s'" % self._name


class PamVerifier:
    """Authenticate against Linux/AD accounts through PAM, plus an allowlist."""

    name = "pam"

    def __init__(self, allowed_users=(), service=None,
                 skip_acct=False, debug=False, resetcreds=False,
                 validate=True):
        import pam  # raises ImportError if python-pam is missing

        self._pam_module = pam
        self._local = threading.local()
        self.debug = bool(debug)
        self.skip_acct = bool(skip_acct)
        self.resetcreds = bool(resetcreds)
        self._lib_does_acct = self._probe_acct_support(pam)

        # Case-insensitive: SSSD lowercases AD names, and users type whatever
        # their Windows habit is.
        self.allowed_users = tuple(allowed_users)
        self._users_lc = frozenset(u.lower() for u in self.allowed_users)
        self.allow_any_user = "*" in self._users_lc
        self.service = service or self._default_service()

        if not self.allowed_users:
            raise RuntimeError(
                "sapmap_auth: no accounts are allowed in. Set SAPMAP_AUTH_USERS "
                "(comma-separated, or '*' for any account PAM accepts), or add "
                "logins to ALLOWED_USERS in modules/core/sapmap_auth.py."
            )

        if validate and not self.allow_any_user:
            self._validate_allowlist()

    def _validate_allowlist(self):
        """Warn about listed names NSS cannot resolve (typos); only a warning,
        since SSSD may not be ready yet at boot and an unresolvable name simply
        never authenticates."""
        unknown = [name for name in self.allowed_users
                   if self._lookup_pw(name) is None]
        if unknown:
            _log("[!] These allowed logins do not resolve on this host and "
                 "will never authenticate: %s" % ", ".join(unknown))

    @staticmethod
    def _default_service():
        if os.path.exists("/etc/pam.d/sapmap"):
            return "sapmap"
        return "login"

    @staticmethod
    def _probe_acct_support(pam_module):
        """Does this python-pam version run the account phase (pam_acct_mgmt)
        itself?  2.0.2 does; older versions do not, and the account phase is
        what enforces SSSD host-access control, so we detect rather than
        assume.  On failure to determine, return False → run it explicitly."""
        try:
            import inspect
            source = inspect.getsource(
                pam_module.PamAuthenticator.authenticate)
        except (OSError, TypeError, AttributeError):
            return False
        return "pam_acct_mgmt" in source

    def _authenticator(self):
        # Constructing PamAuthenticator costs ~9ms (it calls find_library),
        # so keep one per thread.  authenticate() re-inits the handle each
        # call, so reuse across calls is safe.
        auth = getattr(self._local, "auth", None)
        if auth is None:
            auth = self._pam_module.pam()
            self._local.auth = auth
        return auth

    def _debug_log(self, message):
        if self.debug:
            _log("[auth] " + message)

    @staticmethod
    def _lookup_pw(raw):
        """Resolve a typed name to a pwd entry, or None."""
        import pwd
        for candidate in _name_candidates(raw):
            try:
                return pwd.getpwnam(candidate)
            except KeyError:
                continue
            except OSError:
                return None
        return None

    def _in_allowlist(self, raw, entry):
        """Match the typed name and its canonical NSS form, case-insensitively."""
        names_lc = {raw.lower()}
        if entry is not None:
            names_lc.add(entry.pw_name.lower())
        return bool(self._users_lc & names_lc)

    def _pam_check(self, username, password):
        """Run the PAM auth phase and, unless disabled, the account phase."""
        auth = self._authenticator()
        pam_module = self._pam_module

        # resetcreds is off by default: it triggers
        # pam_setcred(PAM_REINITIALIZE_CRED), which with pam_sss/pam_krb5 can
        # try to build a credential cache and fail, turning a correct password
        # into a rejection.  A stateless HTTP check needs no ccache.
        if self.skip_acct or self._lib_does_acct:
            ok = bool(auth.authenticate(username, password,
                                        service=self.service,
                                        resetcreds=self.resetcreds))
            if not ok:
                self._debug_log("rejected %r: code=%s reason=%s"
                                % (username, getattr(auth, "code", None),
                                   getattr(auth, "reason", None)))
            return ok

        # Older python-pam: run the account phase ourselves.
        can_extend = (hasattr(auth, "pam_acct_mgmt")
                      and hasattr(auth, "pam_end"))
        if not can_extend:
            self._debug_log("python-pam lacks pam_acct_mgmt/pam_end, "
                            "running auth phase only")
            return bool(auth.authenticate(username, password,
                                          service=self.service,
                                          resetcreds=self.resetcreds))

        ok = bool(auth.authenticate(username, password,
                                    service=self.service, call_end=False,
                                    resetcreds=self.resetcreds))
        try:
            if not ok:
                self._debug_log("auth phase failed for %r: %s"
                                % (username, getattr(auth, "reason", None)))
                return False
            code = auth.pam_acct_mgmt(auth.handle, 0)
            if code != pam_module.PAM_SUCCESS:
                if code == pam_module.PAM_NEW_AUTHTOK_REQD:
                    detail = "password must be changed"
                elif code == pam_module.PAM_ACCT_EXPIRED:
                    detail = "account expired"
                elif code == pam_module.PAM_PERM_DENIED:
                    detail = "denied by account phase (SSSD host access?)"
                else:
                    detail = "account phase code %s" % code
                self._debug_log("account phase rejected %r: %s"
                                % (username, detail))
                return False
            return True
        finally:
            try:
                auth.pam_end(auth.handle, 0)
            except Exception:
                # Drop the thread-local instance so the next call starts clean.
                self._local.auth = None

    def verify(self, username, password):
        if not username or not password:
            return False

        entry = self._lookup_pw(username)

        if not self.allow_any_user:
            if not self._in_allowlist(username, entry):
                self._debug_log("%r is not in the allowlist" % username)
                return False
        elif entry is None:
            self._debug_log("%r does not resolve via NSS" % username)
            return False

        # Prefer the canonical NSS name for the PAM call and for REMOTE_USER.
        canonical = entry.pw_name if entry is not None else username
        try:
            if self._pam_check(canonical, password):
                return canonical
        except Exception as exc:
            self._debug_log("PAM error for %r: %r" % (canonical, exc))
            self._local.auth = None
        return False

    def describe(self):
        if self.allow_any_user:
            scope = "ANY account PAM accepts"
        else:
            scope = "%d allowed login(s): %s" % (
                len(self.allowed_users), ", ".join(self.allowed_users))
        if self.skip_acct:
            acct = "off"
        elif self._lib_does_acct:
            acct = "on (library)"
        else:
            acct = "on (explicit)"
        return "PAM service '%s', %s, account phase %s, resetcreds %s" % (
            self.service, scope, acct,
            "on" if self.resetcreds else "off")


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class BasicAuthMiddleware:
    """WSGI middleware requiring HTTP Basic auth, delegating to a verifier."""

    def __init__(self, app, verifier, realm="SAPMAP", exclude=(),
                 cache_ttl=300, max_failures=5, lockout_seconds=300):
        self.app = app
        self.verifier = verifier
        self.realm = str(realm).replace('"', "")
        self.exclude = tuple(p for p in exclude if p)
        self.cache_ttl = max(0, int(cache_ttl))
        self.max_failures = max(0, int(max_failures))
        self.lockout_seconds = max(0, int(lockout_seconds))

        self._lock = threading.Lock()
        self._cache = {}        # token -> (expiry, canonical_username)
        self._failures = {}     # lowercased username -> [count, first_ts]
        self._cache_key = secrets.token_bytes(32)

    def _token(self, username, password):
        return hmac.new(
            self._cache_key,
            username.encode("utf-8") + b"\0" + password.encode("utf-8"),
            "sha256",
        ).digest()

    def _cached(self, token, now):
        if not self.cache_ttl:
            return None
        with self._lock:
            record = self._cache.get(token)
            if record is None:
                return None
            expiry, canonical = record
            if expiry <= now:
                self._cache.pop(token, None)
                return None
            return canonical

    def _remember(self, token, canonical, now):
        if not self.cache_ttl:
            return
        with self._lock:
            self._cache[token] = (now + self.cache_ttl, canonical)
            if len(self._cache) > 512:
                for key, record in list(self._cache.items()):
                    if record[0] <= now:
                        self._cache.pop(key, None)

    def _locked_out(self, key, now):
        if not self.max_failures:
            return False
        with self._lock:
            record = self._failures.get(key)
            if not record:
                return False
            count, first = record
            if now - first > self.lockout_seconds:
                self._failures.pop(key, None)
                return False
            return count >= self.max_failures

    def _note_failure(self, key, now):
        if not self.max_failures:
            return
        with self._lock:
            record = self._failures.get(key)
            if not record or now - record[1] > self.lockout_seconds:
                self._failures[key] = [1, now]
            else:
                record[0] += 1

    def _clear_failures(self, key):
        if not self.max_failures:
            return
        with self._lock:
            self._failures.pop(key, None)

    def _is_open_path(self, environ):
        if not self.exclude:
            return False
        path = environ.get("PATH_INFO", "") or "/"
        return any(path.startswith(prefix) for prefix in self.exclude)

    @staticmethod
    def _decode(header):
        """Return (username, password) or None."""
        if not header:
            return None
        parts = header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            return None
        try:
            decoded = base64.b64decode(parts[1].strip(), validate=True)
            text = decoded.decode("utf-8")
        except Exception:
            return None
        user, sep, pwd = text.partition(":")
        if not sep:
            return None
        return user, pwd

    def _respond(self, start_response, status, body, extra_headers=()):
        payload = body.encode("utf-8")
        headers = [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(payload))),
            ("Cache-Control", "no-store"),
        ]
        headers.extend(extra_headers)
        start_response(status, headers)
        return [payload]

    def _challenge(self, start_response):
        return self._respond(
            start_response, "401 Unauthorized", "401 Unauthorized\n",
            [("WWW-Authenticate",
              'Basic realm="%s", charset="UTF-8"' % self.realm)],
        )

    def __call__(self, environ, start_response):
        if self._is_open_path(environ):
            return self.app(environ, start_response)

        creds = self._decode(environ.get("HTTP_AUTHORIZATION"))
        if creds is None:
            return self._challenge(start_response)

        username, password = creds
        now = time.monotonic()
        token = self._token(username, password)

        cached = self._cached(token, now)
        if cached is not None:
            environ["REMOTE_USER"] = cached
            return self.app(environ, start_response)

        key = username.lower()
        if self._locked_out(key, now):
            return self._respond(
                start_response, "429 Too Many Requests",
                "Too many failed attempts. Try again later.\n",
                [("Retry-After", str(self.lockout_seconds))],
            )

        result = self.verifier.verify(username, password)
        if result:
            canonical = result if isinstance(result, str) else username
            self._clear_failures(key)
            self._remember(token, canonical, now)
            environ["REMOTE_USER"] = canonical
            return self.app(environ, start_response)

        self._note_failure(key, now)
        return self._challenge(start_response)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def _resolve_allowed_users():
    """Environment overrides the in-file list when set."""
    from_env = _env_list("SAPMAP_AUTH_USERS")
    if from_env:
        return from_env
    return tuple(str(u).strip() for u in ALLOWED_USERS if str(u).strip())


def _build_verifier(announce):
    backend = (os.environ.get("SAPMAP_AUTH_BACKEND", "auto").strip().lower()
               or "auto")
    if backend not in ("auto", "pam", "static"):
        raise RuntimeError(
            "sapmap_auth: SAPMAP_AUTH_BACKEND must be pam, static or auto")

    if backend in ("auto", "pam"):
        try:
            verifier = PamVerifier(
                allowed_users=_resolve_allowed_users(),
                service=os.environ.get("SAPMAP_AUTH_PAM_SERVICE") or None,
                skip_acct=_env_flag("SAPMAP_AUTH_SKIP_ACCT"),
                debug=_env_flag("SAPMAP_AUTH_DEBUG"),
                resetcreds=_env_flag("SAPMAP_AUTH_RESETCREDS"),
            )
        except ImportError:
            if backend == "pam":
                raise RuntimeError(
                    "sapmap_auth: SAPMAP_AUTH_BACKEND=pam but the python-pam "
                    "package is not installed (pip install python-pam six)")
            if announce:
                _log("[!] python-pam not available, falling back to a single "
                     "static account")
        else:
            if announce:
                _log("[*] Auth enabled via %s" % verifier.describe())
                if hasattr(os, "geteuid") and os.geteuid() != 0:
                    _log("[!] Not running as root. Local accounts need group "
                         "shadow; domain accounts need access to the SSSD "
                         "PAM socket.")
            return verifier

    user = os.environ.get("SAPMAP_USER") or "sapmap"
    password = os.environ.get("SAPMAP_PASSWORD")
    if password:
        if announce:
            _log("[*] Auth enabled. Login: %s / (password from environment)"
                 % user)
    else:
        password = secrets.token_urlsafe(16)
        if announce:
            _log("[*] Auth enabled. Login: %s / %s" % (user, password))
    return StaticVerifier(user, password)


def protect(app, verifier=None, realm=None, exclude=None, announce=True):
    """Wrap a WSGI/Bottle app in Basic auth and return the wrapped callable.

    Returns the app unchanged if SAPMAP_AUTH_DISABLE is truthy.
    """
    if _env_flag("SAPMAP_AUTH_DISABLE"):
        if announce:
            _log("[!] Auth DISABLED via SAPMAP_AUTH_DISABLE")
        return app

    if verifier is None:
        verifier = _build_verifier(announce)

    return BasicAuthMiddleware(
        app,
        verifier,
        realm=realm or os.environ.get("SAPMAP_AUTH_REALM", "SAPMAP"),
        exclude=exclude if exclude is not None else _env_list(
            "SAPMAP_AUTH_EXCLUDE"),
        cache_ttl=_env_int("SAPMAP_AUTH_CACHE_TTL", 300),
        max_failures=_env_int("SAPMAP_AUTH_MAX_FAILURES", 5),
        lockout_seconds=_env_int("SAPMAP_AUTH_LOCKOUT", 300),
    )


def run_protected(app, verifier=None, realm=None, exclude=None, announce=True,
                  **run_kwargs):
    """Drop-in replacement for ``app.run(...)`` that adds Basic auth.

    All keyword args are forwarded to ``bottle.run`` (server_class, quiet,
    host, port, ...), so threading and server behaviour are unchanged.
    """
    import bottle

    wrapped = protect(app, verifier=verifier, realm=realm, exclude=exclude,
                      announce=announce)
    run_kwargs.pop("app", None)
    return bottle.run(app=wrapped, **run_kwargs)
