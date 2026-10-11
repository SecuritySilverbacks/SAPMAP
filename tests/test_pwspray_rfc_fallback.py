"""Tests for the password-spray RFC fallback — issue #106.

DIAG (SAPGUI) can't validate a SYSTEM / COMMUNICATION / SERVICE user
(USTYP B/S/C): SAP refuses the interactive channel BEFORE checking the
password, so a correct and a wrong password both come back as
NO_DIALOG_USER.  The spray now falls back to an RFC logon, which DOES
validate the password for those user types.

Two layers under test:
  * ``sapmap_rfc.rfc_check_credentials`` — the structured RFC check +
    its exception classifier (robust across the ctypes + saprfclib
    backends, which have separate exception hierarchies).
  * ``sapmap_pwspray.check_sprayed_credentials`` — the engine wiring
    that routes NO_DIALOG_USER verdicts to the RFC check and maps the
    result back into hit / miss / locked, tagging the channel.

House style: dependency injection (``rfc_check_fn=`` kwarg) so no
sockets open and no RFC backend is required.
"""
from __future__ import annotations

import pytest

import modules  # noqa: F401 — registers package paths

from sap_default_creds import (SUCCESS, USER_LOCKED, NO_DIALOG_USER,
                               WRONG_PASSWORD)
import sapmap_pwspray as pw
import sapmap_rfc


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeTryLogin:
    """DIAG mock: returns NO_DIALOG_USER for configured service users,
    SUCCESS for configured hits, WRONG_PASSWORD otherwise."""
    def __init__(self, hits=None, nodialog_on=None, locked_on=None):
        self.hits = {k: (SUCCESS, "ok") for k in (hits or [])}
        self.nodialog_on = set(nodialog_on or [])   # (user_up, client)
        self.locked_on = set(locked_on or [])
        self.calls = []

    def __call__(self, host, port, client, user, password, **kw):
        self.calls.append({"user": (user or "").upper(),
                           "password": password, "client": client})
        u = (user or "").upper()
        if (u, client) in self.locked_on:
            return (USER_LOCKED, "locked")
        if (u, client) in self.nodialog_on:
            return (NO_DIALOG_USER, "service user")
        hit = self.hits.get((u, password, client))
        return hit or (WRONG_PASSWORD, "no match")


class _FakeRfcCheck:
    """RFC check mock mirroring sapmap_rfc.rfc_check_credentials's
    signature + (code, detail) contract.  Verdicts keyed by
    (user_up, password, client)."""
    def __init__(self, verdicts=None, default=("WRONG_PASSWORD", "no match")):
        self.verdicts = verdicts or {}
        self.default = default
        self.calls = []

    def __call__(self, host, sysnr, client, user, password, *,
                 saprouter="", timeout=None):
        self.calls.append({"host": host, "sysnr": sysnr, "client": client,
                           "user": (user or "").upper(), "password": password,
                           "saprouter": saprouter, "timeout": timeout})
        return self.verdicts.get(
            ((user or "").upper(), password, client), self.default)


def _spray(pool, *, try_login_fn, rfc_check_fn=None,
           rfc_fallback=True, cap=2, clients=("001",)):
    """Run check_sprayed_credentials with no sleeps / no skip-list."""
    return pw.check_sprayed_credentials(
        "10.0.0.1", 3200, list(clients), pool,
        cap_per_user=cap, early_exit_on_hit=True,
        inter_attempt_sleep_range=(0, 0),
        try_login_fn=try_login_fn,
        rfc_check_fn=rfc_check_fn,
        rfc_fallback_for_service_users=rfc_fallback,
        skip_users=set())


# ===========================================================================
# Engine wiring
# ===========================================================================

def test_rfc_fallback_confirms_service_user_hit():
    """DIAG returns NO_DIALOG_USER; RFC confirms the password → the
    attempt becomes a HIT tagged channel='rfc'."""
    pool = [pw.SprayCandidate(username="SAPJSF", password="secret")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck(verdicts={("SAPJSF", "secret", "001"):
                                   ("SUCCESS", "rfc logon ok")})

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc)

    hits = [r for r in results if r.get("kind") == "hit"]
    assert len(hits) == 1
    assert hits[0]["channel"] == "rfc"
    assert hits[0]["result"] == "SUCCESS"
    assert hits[0]["user"] == "SAPJSF"
    # DIAG was tried once (to learn it's a service user), RFC once.
    assert len(diag.calls) == 1
    assert len(rfc.calls) == 1


def test_rfc_fallback_wrong_password_is_miss():
    """DIAG NO_DIALOG_USER; RFC says wrong password → miss tagged
    channel='rfc' with skipped_reason='rfc_wrong_password'."""
    pool = [pw.SprayCandidate(username="TMSADM", password="bad")]
    diag = _FakeTryLogin(nodialog_on=[("TMSADM", "001")])
    rfc = _FakeRfcCheck(default=("WRONG_PASSWORD", "Name or password is incorrect"))

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc)

    misses = [r for r in results if r.get("kind") == "miss"]
    assert len(misses) == 1
    assert misses[0]["channel"] == "rfc"
    assert misses[0]["skipped_reason"] == "rfc_wrong_password"
    assert misses[0]["result"] == "WRONG_PASSWORD"


def test_rfc_fallback_locked_propagates_and_breaks():
    """RFC reports USER_LOCKED → the attempt is 'locked', the user is
    added to locked_users, and remaining passwords for that user on
    this call are skipped."""
    pool = [pw.SprayCandidate(username="SAPCPIC", password=f"pw{i}")
            for i in range(3)]
    diag = _FakeTryLogin(nodialog_on=[("SAPCPIC", "001")])
    rfc = _FakeRfcCheck(default=("USER_LOCKED", "User is locked"))

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc, cap=3)

    locked = [r for r in results if r.get("kind") == "locked"]
    assert len(locked) == 1
    assert locked[0]["channel"] == "rfc"
    # Only ONE RFC attempt — the lock broke the remaining 2 passwords.
    assert len(rfc.calls) == 1


def test_rfc_fallback_disabled_keeps_diag_miss():
    """With rfc_fallback_for_service_users=False, NO_DIALOG_USER keeps
    its original DIAG-only verdict and the RFC check never runs."""
    pool = [pw.SprayCandidate(username="SAPJSF", password="secret")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck(verdicts={("SAPJSF", "secret", "001"):
                                   ("SUCCESS", "rfc logon ok")})

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc,
                     rfc_fallback=False)

    misses = [r for r in results if r.get("kind") == "miss"]
    assert len(misses) == 1
    assert misses[0]["channel"] == "diag"
    assert misses[0]["skipped_reason"] == "no_dialog_user"
    assert rfc.calls == [], "RFC must not run when the fallback is disabled"


def test_rfc_fallback_expired_password_is_hit():
    """Adversarial-review HIGH finding: an expired-but-CORRECT password
    over RFC (SAP msg 00-046 / 'Enter a new password') proves the
    password is right — the expiry rejection IS a confirmation.  It
    must be a HIT (parity with DIAG's PASSWORD_CHANGE), not a miss.
    Mislabeling it would discard the exact service-user credential the
    #106 feature exists to find (service-user passwords DO expire, and
    RFC is the only channel that can validate them)."""
    pool = [pw.SprayCandidate(username="SAPCPIC", password="correct-but-old")]
    diag = _FakeTryLogin(nodialog_on=[("SAPCPIC", "001")])
    rfc = _FakeRfcCheck(verdicts={("SAPCPIC", "correct-but-old", "001"):
                                   ("PASSWORD_CHANGE",
                                    "Please choose a new password")})

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc)

    hits = [r for r in results if r.get("kind") == "hit"]
    assert len(hits) == 1, (
        "expired-but-correct password over RFC must be a HIT, not a "
        "miss — the expiry rejection confirms the password")
    assert hits[0]["channel"] == "rfc"
    assert hits[0]["result"] == "PASSWORD_CHANGE"


def test_rfc_fallback_connect_failed_is_unreachable_miss():
    """RFC CONNECT_FAILED (gateway unreachable) is NOT a credential
    verdict — the service user stays a miss, flagged unreachable so the
    operator knows to retry rather than assuming a wrong password."""
    pool = [pw.SprayCandidate(username="SAPJSF", password="x")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck(default=("CONNECT_FAILED", "partner not reached"))

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc)

    misses = [r for r in results if r.get("kind") == "miss"]
    assert len(misses) == 1
    assert misses[0]["skipped_reason"] == "no_dialog_user_rfc_unreachable"


def test_rfc_fallback_error_is_unavailable_miss():
    """RFC ERROR (no backend) → miss flagged rfc_unavailable."""
    pool = [pw.SprayCandidate(username="SAPJSF", password="x")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck(default=("ERROR", "rfc backend unavailable"))

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc)

    misses = [r for r in results if r.get("kind") == "miss"]
    assert misses[0]["skipped_reason"] == "no_dialog_user_rfc_unavailable"


def test_diag_hit_tagged_channel_diag():
    """A normal DIAG hit (dialog user) is tagged channel='diag' so the
    UI/report can distinguish the detection signature."""
    pool = [pw.SprayCandidate(username="SAPMAP00", password="andy")]
    diag = _FakeTryLogin(hits=[("SAPMAP00", "andy", "001")])

    results = _spray(pool, try_login_fn=diag)

    hits = [r for r in results if r.get("kind") == "hit"]
    assert len(hits) == 1
    assert hits[0]["channel"] == "diag"


def test_rfc_fallback_tries_each_password_up_to_cap():
    """A service user with 3 candidate passwords + cap=2: the RFC
    fallback must try passwords 1 AND 2 (not just the first), then stop
    at the cap.  Regression guard for the old nodialog short-circuit
    that skipped every password after the first."""
    pool = [pw.SprayCandidate(username="SAPJSF", password=f"pw{i}")
            for i in range(3)]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    # Hit on the SECOND password — proves we don't stop at the first.
    rfc = _FakeRfcCheck(verdicts={("SAPJSF", "pw1", "001"):
                                   ("SUCCESS", "rfc logon ok")})

    results = _spray(pool, try_login_fn=diag, rfc_check_fn=rfc, cap=2)

    rfc_pws = [c["password"] for c in rfc.calls]
    assert rfc_pws == ["pw0", "pw1"], (
        f"RFC must try each password up to cap, hitting on pw1; "
        f"got {rfc_pws}")
    hits = [r for r in results if r.get("kind") == "hit"]
    assert len(hits) == 1 and hits[0]["password"] == "pw1"


def test_rfc_fallback_skips_diag_roundtrip_after_first_nodialog():
    """Once a user is known NO_DIALOG_USER, subsequent passwords skip
    the (wasted) DIAG round-trip and go straight to RFC — DIAG is
    called exactly ONCE for a service user, RFC once per candidate
    (up to cap)."""
    pool = [pw.SprayCandidate(username="SAPJSF", password=f"pw{i}")
            for i in range(2)]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck(default=("WRONG_PASSWORD", "no"))

    _spray(pool, try_login_fn=diag, rfc_check_fn=rfc, cap=2)

    assert len(diag.calls) == 1, (
        f"DIAG should be tried once for a service user, then skipped; "
        f"got {len(diag.calls)} calls")
    assert len(rfc.calls) == 2


def test_rfc_fallback_derives_sysnr_from_dispatcher_port():
    """RFC connects via ASHOST + SYSNR; the engine derives the 2-digit
    sysnr from the dispatcher port (32NN -> NN)."""
    pool = [pw.SprayCandidate(username="SAPJSF", password="x")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck()

    pw.check_sprayed_credentials(
        "10.0.0.1", 3242, ["001"], pool,     # dispatcher port 3242 -> sysnr 42
        cap_per_user=1, inter_attempt_sleep_range=(0, 0),
        try_login_fn=diag, rfc_check_fn=rfc,
        rfc_fallback_for_service_users=True, skip_users=set())

    assert rfc.calls[0]["sysnr"] == "42"


def test_rfc_fallback_threads_saprouter():
    """node.saprouter must reach the RFC check so routed targets work."""
    pool = [pw.SprayCandidate(username="SAPJSF", password="x")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])
    rfc = _FakeRfcCheck()

    pw.check_sprayed_credentials(
        "10.0.0.1", 3200, ["001"], pool,
        cap_per_user=1, inter_attempt_sleep_range=(0, 0),
        saprouter="/H/router/S/3299/H/",
        try_login_fn=diag, rfc_check_fn=rfc,
        rfc_fallback_for_service_users=True, skip_users=set())

    assert rfc.calls[0]["saprouter"] == "/H/router/S/3299/H/"


def test_rfc_fallback_timeout_default_is_unreachable_miss():
    """If the RFC check watchdog times out, the default
    (CONNECT_FAILED) applies → unreachable miss, not a false hit."""
    import time as _t
    pool = [pw.SprayCandidate(username="SAPJSF", password="x")]
    diag = _FakeTryLogin(nodialog_on=[("SAPJSF", "001")])

    def _slow_rfc(host, sysnr, client, user, password, *,
                  saprouter="", timeout=None):
        _t.sleep(2)   # exceeds the 0.2s watchdog below
        return ("SUCCESS", "should never be used")

    results = pw.check_sprayed_credentials(
        "10.0.0.1", 3200, ["001"], pool,
        cap_per_user=1, inter_attempt_sleep_range=(0, 0),
        try_login_fn=diag, rfc_check_fn=_slow_rfc,
        rfc_fallback_for_service_users=True,
        rfc_attempt_timeout_s=0.2, skip_users=set())

    misses = [r for r in results if r.get("kind") == "miss"]
    assert len(misses) == 1
    assert misses[0]["skipped_reason"] == "no_dialog_user_rfc_unreachable"


# ===========================================================================
# rfc_check_credentials classifier — robust across both RFC backends
# ===========================================================================

class _CtypesLogonError(Exception):
    """Shape of the C-SDK backend's typed LogonError (msg_number set)."""
    def __init__(self, msg, msg_class="", msg_number="", key=""):
        super().__init__(msg)
        self.msg_class = msg_class
        self.msg_number = msg_number
        self.key = key


class _CommError(Exception):
    pass
_CommError.__name__ = "CommunicationError"


def test_classify_msg_number_042_is_user_locked():
    exc = _CtypesLogonError("User is locked", msg_class="00",
                            msg_number="042", key="RFC_LOGON_FAILURE")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "USER_LOCKED"


def test_classify_msg_number_152_is_wrong_password():
    exc = _CtypesLogonError("Name or password is incorrect",
                            msg_class="00", msg_number="152",
                            key="RFC_LOGON_FAILURE")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "WRONG_PASSWORD"


def test_classify_pure_backend_nested_wrong_password():
    """The saprfclib backend nests 'logon failed: Name or password is
    incorrect' inside a 'connect failed' wrapper.  The classifier must
    read it as WRONG_PASSWORD, NOT CONNECT_FAILED — the logon-phrase
    check runs before the connect-phrase check."""
    exc = Exception("saprfclib connect failed: logon failed: Name or "
                    "password is incorrect (repeat logon)")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "WRONG_PASSWORD"


def test_classify_pure_backend_nested_locked():
    exc = Exception("saprfclib connect failed: logon failed: User ABC "
                    "is locked")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "USER_LOCKED"


def test_classify_msg_number_046_is_password_change():
    """SAP msg 00-046 = password correct but must be changed.  Must
    classify as PASSWORD_CHANGE (a hit), NOT WRONG_PASSWORD.  This is
    the adversarial-review HIGH finding."""
    exc = _CtypesLogonError("Password must be changed", msg_class="00",
                            msg_number="046", key="RFC_LOGON_FAILURE")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "PASSWORD_CHANGE"


@pytest.mark.parametrize("text", [
    "logon failed: Please choose a new password",
    "Enter a new password",
    "Password has expired",
    "saprfclib connect failed: logon failed: Kennwort ist abgelaufen",
    "Bitte neues Kennwort vergeben",
])
def test_classify_expired_password_text_is_password_change(text):
    """Expired-password rejection text (EN + DE), incl. the pure-backend
    nested wrapper, must classify as PASSWORD_CHANGE — the text check
    runs before the wrong-password + typed-LogonError fallbacks."""
    exc = Exception(text)
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "PASSWORD_CHANGE", f"{text!r} -> {code}"


def test_classify_communication_error_is_connect_failed():
    exc = _CommError("partner 'host:sapgw00' not reached")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "CONNECT_FAILED"


def test_classify_typed_logon_error_without_subreason_is_wrong_password():
    """A LogonError with no recognised message text is still a logon
    rejection → treat as wrong password, not an inconclusive error."""
    exc = _CtypesLogonError("logon failed", key="RFC_LOGON_FAILURE")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "WRONG_PASSWORD"


def test_classify_unknown_is_error():
    exc = Exception("something totally unexpected happened")
    code, _ = sapmap_rfc._classify_rfc_logon_exception(exc)
    assert code == "ERROR"


def test_rfc_check_credentials_returns_error_when_no_backend(monkeypatch):
    """When no RFC backend can be loaded, rfc_check_credentials returns
    ERROR (never raises) so the spray engine degrades cleanly."""
    def _boom():
        raise ImportError("No RFC backend available")
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", _boom)

    code, detail = sapmap_rfc.rfc_check_credentials(
        "10.0.0.1", "00", "001", "SAPJSF", "x")
    assert code == "ERROR"
    assert "backend unavailable" in detail


# ===========================================================================
# GUI wiring — modal toggle → collector → backend SprayConfig
# ===========================================================================

def _html():
    import sapmap_html
    return sapmap_html.get_html()


def _gui_src():
    import inspect
    import sapmap_gui
    return inspect.getsource(sapmap_gui)


def test_modal_has_rfc_service_user_checkbox_default_on():
    """The pwspray modal exposes the RFC service-user toggle, checked
    by default (safe + strictly more complete)."""
    html = _html()
    assert 'id="pws-rfc-service-users" checked' in html, (
        "modal must carry the pws-rfc-service-users checkbox, default "
        "checked")
    # Operator-facing explanation names the user types + the channel.
    assert "USTYP B/S/C" in html
    assert "issue #106" in html


def test_collector_emits_rfc_toggle():
    """_pwsprayCollectConfig must read the checkbox into the launch
    config body under the backend's field name."""
    html = _html()
    assert ("rfc_fallback_for_service_users:\n"
            "      document.getElementById('pws-rfc-service-users').checked"
            in html), (
        "collector must map the checkbox to "
        "rfc_fallback_for_service_users")


def test_backend_threads_rfc_toggle_into_sprayconfig():
    """Both spray routes (landscape + per-node) must parse the toggle
    from the body and pass it to SprayConfig."""
    src = _gui_src()
    # Parsed from the body (landscape route uses _strict_bool, per-node
    # uses body.get — both default True).
    assert 'rfc_fallback_for_service_users", True)' in src or \
           'rfc_fallback_for_service_users", True)' in src
    # Threaded into SprayConfig.
    assert "rfc_fallback_for_service_users=(" in src, (
        "SprayConfig construction must receive the toggle")


def test_spray_attempt_record_carries_channel():
    """The persisted SprayAttempt must record which channel confirmed
    the verdict so the loot JSONL + report can show DIAG vs RFC."""
    import dataclasses
    fields = {f.name for f in dataclasses.fields(pw.SprayAttempt)}
    assert "channel" in fields, (
        "SprayAttempt must have a 'channel' field (diag/rfc)")
