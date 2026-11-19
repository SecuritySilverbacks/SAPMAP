"""Regression: BAPI_USER_CREATE1 must send a valid internal DATS for the
LOGONDATA valid-from/valid-to, never a blank one (issue #215).

Root cause: a type-D (DATS) field's ABAP-initial value is "00000000", not
blanks.  The pure-Python RFC backend (saprfclib) pads an unset/empty DATS
structure field with spaces, and SAP's BAPI_USER_CREATE1 then rejects the
all-blank valid-from GLTGV as "Invalid date" (message 00/302).  Before the
saprfclib fallback the C SDK sent "00000000", so the user-create path worked;
afterwards it broke with no source change — the valid-from was never set
explicitly.  The fix sets GLTGV/GLTGB explicitly; these tests fail if either
regresses to absent/blank.

The tests never touch the network — _get_connection is patched so the create
path runs entirely in-memory and we inspect the exact kwargs handed to the
BAPI.
"""
from __future__ import annotations

import re
from unittest.mock import patch, MagicMock

from sapmap_models import SAPNode, Credentials
from sapmap_rfc import (
    create_user_via_bapi, canary_create_user_probe,
    SAP_DATS_INITIAL, SAP_DATS_FOREVER, BAPI_USER_CREATE,
)

_DATS_RE = re.compile(r"^\d{8}$")   # internal YYYYMMDD, 8 digits, no blanks


class _RecordingConn:
    """Minimal fake RFC connection: records every .call() and returns a
    plausible RETURN per function module so the create flow proceeds."""

    def __init__(self):
        self.calls = []  # list[(func_name, kwargs)]

    def call(self, func_name, **kwargs):
        self.calls.append((func_name, kwargs))
        if func_name == "BAPI_USER_GET_DETAIL":
            # existence pre-check → report "does not exist" so create runs
            return {"RETURN": [{"TYPE": "E",
                                "MESSAGE": "User does not exist"}],
                    "ADDRESS": {}}
        if func_name == "BAPI_USER_DELETE":
            return {"RETURN": [{"TYPE": "S", "MESSAGE": "User deleted"}]}
        # BAPI_USER_CREATE1 / BAPI_USER_PROFILES_ASSIGN / anything else
        return {"RETURN": [{"TYPE": "S", "MESSAGE": "ok"}]}

    def logondata_for(self, func_name):
        for name, kwargs in self.calls:
            if name == func_name:
                return kwargs.get("LOGONDATA")
        return None


def _mgr(conn):
    """A context manager (like _get_connection) yielding `conn`."""
    m = MagicMock()
    m.__enter__.return_value = conn
    m.__exit__.return_value = False
    return m


def _node():
    return SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.1",
                   system_type="ABAP")


def _creds():
    return Credentials(username="SAPMAP00", password="x",
                       client="001", instance_nr="00", verified=True)


def _assert_valid_logondata_dates(logondata, *, require_gltgb=True):
    assert logondata is not None, "no BAPI_USER_CREATE1 call was recorded"
    # Valid-from MUST be present and a valid internal DATS — never blank,
    # which is exactly what the saprfclib backend would send for an unset
    # field and what SAP rejects as "Invalid date" (#215).
    assert "GLTGV" in logondata, "LOGONDATA must set GLTGV (valid-from) explicitly"
    gltgv = logondata["GLTGV"]
    assert isinstance(gltgv, str) and _DATS_RE.match(gltgv), \
        f"GLTGV must be an 8-digit internal DATS, got {gltgv!r}"
    assert gltgv.strip(), "GLTGV must not be blank/whitespace"
    if require_gltgb:
        assert "GLTGB" in logondata, "LOGONDATA must set GLTGB (valid-to)"
        gltgb = logondata["GLTGB"]
        assert isinstance(gltgb, str) and _DATS_RE.match(gltgb), \
            f"GLTGB must be an 8-digit internal DATS, got {gltgb!r}"


def test_create_user_via_bapi_sends_valid_dats():
    """The main create path sends a non-blank, well-formed GLTGV/GLTGB."""
    conn = _RecordingConn()
    with patch("sapmap_rfc._get_connection", return_value=_mgr(conn)):
        res = create_user_via_bapi(
            _node(), username="SAPMAP01", password="Secret123!",
            client="001", creds=_creds(), verify_logon=False)
    assert res["success"] is True, res
    _assert_valid_logondata_dates(conn.logondata_for(BAPI_USER_CREATE))


def test_canary_probe_sends_valid_dats():
    """Layer-4 canary create+delete also sends a valid non-blank DATS."""
    conn = _RecordingConn()
    with patch("sapmap_rfc._get_connection", return_value=_mgr(conn)):
        res = canary_create_user_probe(
            _node(), creds=_creds(), username="ZZCANARY")
    assert res["created"] is True, res
    _assert_valid_logondata_dates(conn.logondata_for(BAPI_USER_CREATE))


def test_dats_constants_are_well_formed():
    """Guard the constants themselves: both are 8-digit internal DATS."""
    assert _DATS_RE.match(SAP_DATS_INITIAL), SAP_DATS_INITIAL
    assert _DATS_RE.match(SAP_DATS_FOREVER), SAP_DATS_FOREVER
    assert SAP_DATS_INITIAL == "00000000"   # ABAP-initial → SAP defaults it
    assert SAP_DATS_FOREVER == "99991231"   # far-future "no expiry"
