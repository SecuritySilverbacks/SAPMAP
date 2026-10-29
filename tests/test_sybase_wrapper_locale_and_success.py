#!/usr/bin/env python3
"""Regression tests for the Sybase writer's locale normalization and
honest success detection (live ABA report, kernel 753, 2026-10-29).

Symptom: GW SAPXPG + sybase writer confirmed OS-exec (whoami=abaadm) and
reported all 6 SQL groups "✓ committed", yet SAPMAP00 never landed and the
RFC login verification failed with "Name or password is incorrect".

Root cause: the remote host runs with LANG=C.UTF-8 (sapxpg inherits it),
but Sybase OpenClient's locales.dat has no "C.UTF-8" entry.  isql aborted
in CS-Library localization init BEFORE connecting — running NO SQL — with:

    Using locale name "C.UTF-8" defined in environment variable LANG
    Locale name "C.UTF-8" doesn't exist in your .../locales.dat file
    An error occurred when attempting to allocate localization-related
    structures.

...yet isql still exited 0, which the writer read as "committed".

Fix (two parts):
  1. The wrapper clears LANG/LC_* before isql so CS-Library falls back to
     the always-present 'default' locales.dat entry.
  2. Success is no longer "EXIT==0": the writer also scans isql stdout for
     fatal CS-Library / CT-LIB / ASE signatures, so a 0 exit with a locale
     abort (or a login/connect/SQL error) is reported as FAILED.
"""
from __future__ import annotations

import pytest

import modules  # noqa: F401 — registers package paths


def _import_writers_safely():
    """sap_db_sql_writers has a circular dep with sapmap_exploit that only
    resolves cleanly when sapmap_exploit is loaded first (mirrors
    tests/test_sybase_wrapper_interfaces_lenient.py)."""
    import sapmap_exploit  # noqa: F401 — primes the chain
    import sap_db_sql_writers as _w
    return _w


def _wrapper(sid: str = "ABA", pw: str = "", user: str = "sapsa") -> str:
    _w = _import_writers_safely()
    return _w._build_sybase_wrapper_script(sid, db_password=pw, db_user=user)


# ---------------------------------------------------------------------------
# Part 1 — locale normalization in the wrapper
# ---------------------------------------------------------------------------

def test_wrapper_clears_locale_before_isql():
    """Wrapper must clear LANG + LC_ALL (at minimum) so CS-Library falls
    back to the 'default' locales.dat entry instead of aborting on an
    unknown C.UTF-8 locale."""
    body = _wrapper()
    assert "unset LANG LC_ALL" in body, (
        "wrapper must `unset LANG LC_ALL ...` before isql — the live ABA "
        "bug was isql aborting on C.UTF-8 which isn't in locales.dat")


def test_wrapper_unset_precedes_isql_invocation():
    """The locale unset must come BEFORE the isql invocation line, else
    isql still inherits the bad LANG."""
    body = _wrapper()
    unset_pos = body.find("unset LANG LC_ALL")
    isql_pos = body.find('"$ISQL" -U"$DBUSER"')
    assert unset_pos != -1, "locale unset missing from wrapper"
    assert isql_pos != -1, "isql invocation missing from wrapper"
    assert unset_pos < isql_pos, (
        "locale unset must precede the isql invocation so isql doesn't "
        "inherit LANG=C.UTF-8")


def test_wrapper_unset_swallows_failure():
    """The unset must not abort the wrapper (guard with `|| true`)."""
    body = _wrapper()
    assert "unset LANG LC_ALL LC_CTYPE LC_MESSAGES LC_COLLATE LC_NUMERIC 2>/dev/null || true" in body


# ---------------------------------------------------------------------------
# Part 2 — honest success detection (_sybase_isql_output_fatal)
# ---------------------------------------------------------------------------

@pytest.fixture
def fatal():
    return _import_writers_safely()._sybase_isql_output_fatal


# The exact lines SAP isql emitted on ABA before the fix.
_LOCALE_ABORT = [
    "Your sybase home directory is /sybase/ABA. Check the environment variable SYBASE",
    'Using locale name "C.UTF-8" defined in environment variable LANG',
    'Locale name "C.UTF-8" doesn\'t exist in your /sybase/ABA/locales/locales.dat file',
    "An error occurred when attempting to allocate localization-related structures.",
    "SAPMAP:EXIT=0",
]
_SUCCESS = [
    "SAPMAP:iface=direct-connect host:port=wdflbmd7323:4901",
    "(1 row affected)",
    "SAPMAP:EXIT=0",
]


def test_fatal_flags_locale_abort(fatal):
    """The live-observed locale abort (EXIT=0, zero rows) must be fatal."""
    reason = fatal(_LOCALE_ABORT)
    assert reason and "locale" in reason.lower(), (
        f"locale abort must be flagged fatal; got {reason!r}")


def test_fatal_clean_on_success(fatal):
    """A real successful write ((1 row affected), EXIT=0) must NOT be
    flagged."""
    assert fatal(_SUCCESS) is None


def test_fatal_benign_sybase_home_not_flagged(fatal):
    """isql's harmless 'Your sybase home directory is /sybase/ABA' note
    must not trip the 'no /sybase/' locator-failure signature."""
    assert fatal([
        "Your sybase home directory is /sybase/ABA.",
        "(1 row affected)",
        "SAPMAP:EXIT=0",
    ]) is None


def test_fatal_flags_login_failed(fatal):
    assert fatal(["Msg 4002, Level 14, State 1:",
                  'Server "ABA": Login failed.',
                  "SAPMAP:EXIT=0"]) is not None


def test_fatal_flags_ct_connect(fatal):
    assert fatal(["CT-LIBRARY error:",
                  "ct_connect(): directory service layer: ...",
                  "SAPMAP:EXIT=255"]) is not None


def test_fatal_flags_server_name_not_found(fatal):
    assert fatal(["Requested server name not found.",
                  "SAPMAP:EXIT=255"]) is not None


def test_fatal_flags_locator_miss(fatal):
    assert fatal(["SAPMAP: no /sybase/*/OCS-*/bin/isql on target"]) is not None


def test_fatal_server_error_level_11_plus_is_fatal(fatal):
    """Any ASE server error at level >= 11 (missing object, constraint,
    duplicate key) must be fatal — isql exits non-zero on these anyway, so
    treating them as fatal keeps the verdict honest and the operator sees
    the real Msg number."""
    assert fatal(["Msg 208, Level 16, State 1:",
                  "SAPSR3.USR02 not found.",
                  "SAPMAP:EXIT=0"]) is not None
    assert fatal(["Msg 2601, Level 14, State 3:",
                  "Attempt to insert duplicate key row",
                  "SAPMAP:EXIT=0"]) is not None


def test_fatal_flags_zero_rows_affected(fatal):
    """An explicit '(0 rows affected)' on a DML write means the statement
    matched/inserted nothing — the write silently did not land."""
    assert fatal(["SAPMAP:iface=direct-connect host:port=h:4901",
                  "(0 rows affected)",
                  "SAPMAP:EXIT=0"]) is not None


def test_fatal_positive_rows_affected_not_flagged(fatal):
    """A positive '(1 row affected)' must never be mistaken for the
    zero-rows tripwire."""
    assert fatal(["(1 row affected)", "SAPMAP:EXIT=0"]) is None
    assert fatal(["(10 rows affected)", "SAPMAP:EXIT=0"]) is None


def test_fatal_flags_csi_lib_load_failure(fatal):
    """CSI security library load failure for -X encrypted login must be
    fatal — no SQL runs when -X can't initialise."""
    assert fatal(["ct_init(): ... comn_csicorelib_load failed",
                  "SAPMAP:EXIT=255"]) is not None


def test_fatal_flags_password_encryption_reject(fatal):
    assert fatal(["Adaptive Server requires password encryption for login",
                  "SAPMAP:EXIT=255"]) is not None


def test_fatal_second_locale_anchor(fatal):
    """The locales.dat anchor catches locale aborts whose alloc-error
    wording differs by OCS version."""
    assert fatal(['Locale name "C.UTF-8" doesn\'t exist in your '
                  '/sybase/ABA/locales/locales.dat file',
                  "SAPMAP:EXIT=0"]) is not None


def test_fatal_none_on_empty(fatal):
    assert fatal([]) is None
    assert fatal(None) is None
