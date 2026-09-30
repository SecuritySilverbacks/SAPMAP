"""Offline tests for sapmap_ucon (issue #27).

Two shapes:
  * check_ucon_status posture logic against a stubbed RFC conn.
  * poc_disable_ucon delegates to tier3_set_param with the right
    param, value, and technique id.  No live RFC involved.
"""
from unittest.mock import MagicMock, patch
from contextlib import contextmanager

from sapmap_models import Credentials, SAPNode
from sapmap_evasion_gate import TIER3_TECHNIQUES

import sapmap_ucon


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node():
    n = SAPNode(sid="NPL", hostname="vhcalnplci", ip="192.168.2.106")
    return n


def _creds():
    return Credentials(username="SAPMAP00", password="x",
                        client="001", instance_nr="00", verified=True)


class _FakeConn:
    """Minimal RFCConnection stand-in — records calls and returns
    canned responses keyed by FM name."""
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def call(self, fm, **kwargs):
        self.calls.append((fm, kwargs))
        r = self.responses.get(fm)
        if isinstance(r, Exception):
            raise r
        if callable(r):
            return r(**kwargs)
        return r or {}


@contextmanager
def _patched_conn(fake):
    """Patch sapmap_rfc._get_connection to yield the fake."""
    @contextmanager
    def _cm(*a, **kw):
        yield fake
    with patch("sapmap_rfc._get_connection", _cm):
        yield


# ---------------------------------------------------------------------------
# Registry wiring
# ---------------------------------------------------------------------------

def test_technique_registered_in_tier3_catalogue():
    """The Tier 3 gate must know about the new technique id so
    assert_evasion_allowed doesn't refuse with 'unknown technique'."""
    assert sapmap_ucon.UCON_TECHNIQUE_ID in TIER3_TECHNIQUES
    label = TIER3_TECHNIQUES[sapmap_ucon.UCON_TECHNIQUE_ID].label
    assert "UCON" in label
    assert "#27" in label


def test_phase_label_known_and_unknown():
    assert sapmap_ucon.phase_label("A") == "Active/Final"
    assert sapmap_ucon.phase_label("L") == "Logging"
    assert sapmap_ucon.phase_label("E") == "Evaluation"
    # Unknown code passes through unchanged (better than a lying '?').
    assert sapmap_ucon.phase_label("Z") == "Z"
    assert sapmap_ucon.phase_label("") == "?"


# ---------------------------------------------------------------------------
# check_ucon_status posture matrix
# ---------------------------------------------------------------------------

def _fake_read_table(rows_by_where):
    """Build a RFC_READ_TABLE stub that returns different row-counts
    depending on the OPTIONS clause (used to fake phase filters)."""
    def _impl(**kw):
        opts = kw.get("OPTIONS") or []
        where = "".join(o.get("TEXT", "") for o in opts)
        n = rows_by_where.get(where, rows_by_where.get("__default__", 0))
        return {"DATA": [{"WA": "x"}] * n,
                "FIELDS": [{"FIELDNAME": "FUNCNAME"}]}
    return _impl


def test_status_off_when_uninitialized():
    fake = _FakeConn({
        "TH_GET_PARAMETER": {"PARAMETER_VALUE": "0"},
        "RFC_READ_TABLE": _fake_read_table({"__default__": 0}),
    })
    with _patched_conn(fake):
        s = sapmap_ucon.check_ucon_status(_node(), _creds())
    assert s["ok"] is True
    assert s["param_value"] == "0"
    assert s["enforcing"] is False
    assert s["initialized"] is False
    assert s["posture"] == "off"


def test_status_initialized_but_off():
    fake = _FakeConn({
        "TH_GET_PARAMETER": {"PARAMETER_VALUE": "0"},
        "RFC_READ_TABLE": _fake_read_table({
            "__default__": 20996,           # any non-empty read
            "ACTUAL_PHASE = 'A'": 1,        # one Final-phase RFM
            "ACTUAL_PHASE = 'L'": 20000,
            "ACTUAL_PHASE = 'E'": 995,
        }),
    })
    with _patched_conn(fake):
        s = sapmap_ucon.check_ucon_status(_node(), _creds())
    assert s["enforcing"] is False
    assert s["initialized"] is True
    assert s["posture"] == "initialized-but-off"


def test_status_enforcing_with_final_phase_fm():
    fake = _FakeConn({
        "TH_GET_PARAMETER": {"PARAMETER_VALUE": "1"},
        "RFC_READ_TABLE": _fake_read_table({
            "__default__": 20996,
            "ACTUAL_PHASE = 'A'": 1,
            "ACTUAL_PHASE = 'L'": 20000,
            "ACTUAL_PHASE = 'E'": 995,
        }),
    })
    with _patched_conn(fake):
        s = sapmap_ucon.check_ucon_status(_node(), _creds())
    assert s["enforcing"] is True
    assert s["initialized"] is True
    assert s["final_phase_count"] == 1
    assert s["posture"] == "enforcing"


def test_status_final_phase_empty_when_no_A_rows():
    fake = _FakeConn({
        "TH_GET_PARAMETER": {"PARAMETER_VALUE": "1"},
        "RFC_READ_TABLE": _fake_read_table({
            "__default__": 100,
            "ACTUAL_PHASE = 'A'": 0,
            "ACTUAL_PHASE = 'L'": 100,
            "ACTUAL_PHASE = 'E'": 0,
        }),
    })
    with _patched_conn(fake):
        s = sapmap_ucon.check_ucon_status(_node(), _creds())
    assert s["posture"] == "final-phase-empty"


def test_status_reports_connection_error_gracefully():
    def _boom(*a, **kw):
        raise RuntimeError("no route to host")
    with patch("sapmap_rfc._get_connection", _boom):
        s = sapmap_ucon.check_ucon_status(_node(), _creds())
    assert s["ok"] is False
    assert "no route to host" in s["error"]


# ---------------------------------------------------------------------------
# poc_disable_ucon — delegates and passes the right args
# ---------------------------------------------------------------------------

def test_poc_delegates_to_tier3_set_param_with_ucon_technique():
    node = _node()
    creds = _creds()
    fake_state = MagicMock(name="state")

    captured_kwargs = {}
    def _fake_tier3(state, n, param, value, **kwargs):
        captured_kwargs.update(kwargs)
        captured_kwargs["param"] = param
        captured_kwargs["value"] = value
        return {"ok": True, "applied": True, "error": "",
                "baseline_value": "1",
                "live_after_write": "0",
                "live_after_restore": "1"}

    fake_conn = _FakeConn({
        "TH_GET_PARAMETER": {"PARAMETER_VALUE": "1"},
        "RFC_READ_TABLE": _fake_read_table({"__default__": 0}),
    })

    with _patched_conn(fake_conn), \
         patch("sapmap_evasion_tier3.tier3_set_param",
               side_effect=_fake_tier3):
        out = sapmap_ucon.poc_disable_ucon(
            fake_state, node, creds, hold_seconds=5.0)

    assert captured_kwargs["param"] == "ucon/rfc/active"
    assert captured_kwargs["value"] == "0"
    assert captured_kwargs["technique"] == sapmap_ucon.UCON_TECHNIQUE_ID
    assert captured_kwargs.get("hold_seconds") == 5.0
    assert out["ok"] is True
    assert out["applied"] is True
    assert out["technique"] == sapmap_ucon.UCON_TECHNIQUE_ID
    # No canary asked for → canary_before / canary_after stay None.
    assert out["canary_before"] is None
    assert out["canary_after"] is None


def test_poc_probes_canary_when_asked():
    node = _node()
    creds = _creds()
    fake_state = MagicMock(name="state")

    class _RejectException(Exception):
        pass

    def _tier3_ok(*a, **kw):
        return {"ok": True, "applied": True, "error": "",
                "baseline_value": "1", "live_after_write": "0",
                "live_after_restore": "1"}

    # STFC_CONNECTION raises the UCON reject string on each call —
    # simulating enforced blocking both pre-flip and post-restore.
    def _stfc(**kw):
        raise _RejectException(
            "RFC_ABAP_MESSAGE: UCON RFC Rejected; "
            "Called Function :STFC_CONNECTION")

    fake_conn = _FakeConn({
        "TH_GET_PARAMETER": {"PARAMETER_VALUE": "1"},
        "RFC_READ_TABLE": _fake_read_table({"__default__": 0}),
        "STFC_CONNECTION": _stfc,
    })

    with _patched_conn(fake_conn), \
         patch("sapmap_evasion_tier3.tier3_set_param",
               side_effect=_tier3_ok):
        out = sapmap_ucon.poc_disable_ucon(
            fake_state, node, creds, hold_seconds=0.0,
            canary_fm="STFC_CONNECTION")

    assert out["canary_before"] is not None
    assert out["canary_after"] is not None
    assert out["canary_before"]["rejected_by_ucon"] is True
    assert out["canary_after"]["rejected_by_ucon"] is True
    # canary_during is documented as None in the single-thread path.
    assert out["canary_during"] is None
