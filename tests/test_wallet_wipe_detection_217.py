"""Silent-wipe detection for the SNC wallet + forged-ticket bundles.

Issue #217 — a live pentest in 2026-11 lost the looted-PSE SNC wallet
plus the forged-ticket bundle between two consecutive autosaves with no
operator action.  Code inspection could not locate the wipe site, so the
defence lives in ``save_state``: before overwriting state to disk,
compare the pending payload to the most-recent prior autosave and, on
populated → empty regression, drop a ``.WIPE_TRACE_<ts>.txt`` beside the
save with the stack trace at the save call.

The save still completes — the trace is diagnostic, not a veto — so
these tests check:
  1. a legitimate first save (no prior autosave) leaves no trace;
  2. a populated → still-populated save leaves no trace;
  3. a populated → EMPTY save writes a trace carrying the stack trace
     and the diff, and emits a banner on stderr;
  4. the detection is scoped to the fields #217 called out
     (snc_credentials + forged_tickets) and does not fire for
     unrelated structural changes (nodes count dropping, etc);
  5. the detection does not fire on the FIRST autosave of a session
     where the wallet legitimately starts empty.

The tests use a tmp_path state dir via STATE_DIR monkeypatch so the
real ``states/`` directory stays untouched.
"""
import json
import os
import sys

import pytest

import sapmap_state as _state_mod
from sapmap_state import save_state
from sapmap_models import (
    SAPMAPState, SAPNode, SNCCredential, ForgedTicket,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """Redirect STATE_DIR into tmp_path for the test."""
    d = tmp_path / "states"
    d.mkdir()
    monkeypatch.setattr(_state_mod, "STATE_DIR", str(d))
    # RFC cache file path also lives under STATE_DIR — keep it consistent.
    monkeypatch.setattr(_state_mod, "RFC_CACHE_FILE",
                        str(d / ".sapmap_rfc_cache.json"))
    return str(d)


def _populated_state() -> SAPMAPState:
    """Build a state carrying a looted PSE + one forged ticket."""
    s = SAPMAPState()
    s.add_node(SAPNode(sid="NPL", hostname="nplhost", ip="10.0.0.1"))
    s.add_snc_credential(SNCCredential(
        source_sid="NPL",
        pse_path="/tmp/NPL/SAPSYS.pse",
        snc_identity="p:CN=NPL,O=SAP",
        source_label="nplhost",
        looted_at="2026-11-21T10:00:00",
    ))
    s.forged_tickets.append(ForgedTicket(
        user="SAP*",
        client="000",
        sid="NPL",
        cookie_b64="AAAA",
        forged_at="2026-11-21T10:01:00",
    ))
    return s


def _tracked_counts(filepath: str) -> dict:
    """Read the saved payload and return the #217 tracked counts."""
    with open(filepath, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return {
        "snc_credentials": len(payload.get("snc_credentials") or {}),
        "forged_tickets":  len(payload.get("forged_tickets") or []),
    }


def _wipe_traces_in(state_dir: str) -> list:
    return sorted(
        f for f in os.listdir(state_dir)
        if ".WIPE_TRACE_" in f
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_first_save_leaves_no_trace(state_dir):
    """A fresh engagement's first autosave must not fire the detector —
    there is no prior file to compare against."""
    s = _populated_state()
    path = os.path.join(state_dir, "first.sapmap")
    save_state(s, path)
    assert os.path.isfile(path)
    assert _wipe_traces_in(state_dir) == []
    assert _tracked_counts(path) == {"snc_credentials": 1, "forged_tickets": 1}


def test_populated_to_populated_leaves_no_trace(state_dir):
    """Steady-state save (wallet + tickets stay populated) must not fire
    the detector.  Covers the ordinary autosave case."""
    s = _populated_state()
    save_state(s, os.path.join(state_dir, "first.sapmap"))

    # Add another looted PSE + another forged ticket — still populated.
    s.add_snc_credential(SNCCredential(
        source_sid="S4H",
        pse_path="/tmp/S4H/SAPSYS.pse",
        snc_identity="p:CN=S4H,O=SAP",
    ))
    s.forged_tickets.append(ForgedTicket(
        user="DDIC", client="000", sid="S4H",
        cookie_b64="BBBB",
        forged_at="2026-11-21T10:05:00",
    ))
    save_state(s, os.path.join(state_dir, "second.sapmap"))
    assert _wipe_traces_in(state_dir) == []


def test_wallet_wipe_fires_trace(state_dir, capsys):
    """The #217 scenario — populated wallet one autosave, empty the
    next.  Expect a .WIPE_TRACE_<ts>.txt beside the new save plus a
    stderr banner."""
    s = _populated_state()
    save_state(s, os.path.join(state_dir, "first.sapmap"))

    # Simulate the bug: wallet + tickets wiped in-memory between saves.
    s.snc_credentials.clear()
    s.forged_tickets.clear()

    second = os.path.join(state_dir, "second.sapmap")
    save_state(s, second)

    traces = [t for t in os.listdir(state_dir)
              if t.startswith("second.sapmap.WIPE_TRACE_")]
    assert len(traces) == 1, f"expected one trace, got {traces}"
    trace_body = open(os.path.join(state_dir, traces[0])).read()
    assert "snc_credentials" in trace_body
    assert "forged_tickets" in trace_body
    assert "1  ->  0" in trace_body
    # Stack trace must be present — the forensic signal #217 asked for.
    assert "save_state" in trace_body
    # Save completed despite the warning.
    assert os.path.isfile(second)
    assert _tracked_counts(second) == {"snc_credentials": 0,
                                       "forged_tickets": 0}
    # Loud stderr banner.
    err = capsys.readouterr().err
    assert "silent-wipe detected" in err
    assert "issue #217" in err


def test_forged_tickets_only_wipe(state_dir):
    """A wipe of forged_tickets alone (wallet still populated) must
    still fire the detector — forged tickets are loot too."""
    s = _populated_state()
    save_state(s, os.path.join(state_dir, "first.sapmap"))
    s.forged_tickets.clear()
    second = os.path.join(state_dir, "second.sapmap")
    save_state(s, second)
    traces = [t for t in os.listdir(state_dir)
              if t.startswith("second.sapmap.WIPE_TRACE_")]
    assert len(traces) == 1
    body = open(os.path.join(state_dir, traces[0])).read()
    assert "forged_tickets" in body
    # Wallet did NOT regress, so no wallet row.
    wiped_lines = [ln for ln in body.splitlines()
                   if "->" in ln and "0" in ln]
    assert any("forged_tickets" in ln for ln in wiped_lines)
    assert not any("snc_credentials" in ln for ln in wiped_lines)


def test_node_removal_does_not_fire(state_dir):
    """Dropping a node is unrelated to #217's tracked fields.  The
    detector must stay quiet or it generates noise on ordinary
    operator-driven cleanups."""
    s = _populated_state()
    s.add_node(SAPNode(sid="SBD", hostname="sbd", ip="10.0.0.2"))
    save_state(s, os.path.join(state_dir, "first.sapmap"))
    s.remove_node("SBD")
    save_state(s, os.path.join(state_dir, "second.sapmap"))
    assert _wipe_traces_in(state_dir) == []


def test_empty_prior_does_not_false_alarm(state_dir):
    """A prior autosave with an empty wallet must not fool the detector
    into firing when the pending save is also empty.  Covers a session
    that never acquired loot."""
    s = SAPMAPState()
    s.add_node(SAPNode(sid="NPL", hostname="nplhost", ip="10.0.0.1"))
    save_state(s, os.path.join(state_dir, "first.sapmap"))

    # Add another unrelated node; wallet stays empty on both saves.
    s.add_node(SAPNode(sid="S4H", hostname="s4h", ip="10.0.0.3"))
    save_state(s, os.path.join(state_dir, "second.sapmap"))
    assert _wipe_traces_in(state_dir) == []


def test_tracked_counts_tolerates_legacy_schema(state_dir):
    """A .sapmap written before #137 has no snc_credentials key at all.
    _tracked_field_counts must degrade to zero so the diff doesn't
    report a phantom regression on the first #137-aware save."""
    legacy_path = os.path.join(state_dir, "legacy.sapmap")
    with open(legacy_path, "w", encoding="utf-8") as f:
        # Schema from before the wallet existed — no snc_credentials / no
        # forged_tickets key.  Operator reopens this old session and the
        # first autosave should NOT fire the detector.
        json.dump({
            "version": "0.9",
            "timestamp": "2026-09-01T00:00:00",
            "scan_config": {},
            "nodes": {},
            "connections": [],
        }, f)

    s = _populated_state()
    second = os.path.join(state_dir, "second.sapmap")
    save_state(s, second)
    # No regression — legacy counts are zero, current are positive.
    assert _wipe_traces_in(state_dir) == []


def test_exclude_self_from_prior_lookup(state_dir):
    """The prior-autosave lookup must NEVER pick up the save about to
    be written itself — otherwise a same-path overwrite would always
    look like a no-op diff.  Instead the scan should find an older
    file in the same directory.  This test verifies the exclude_path
    plumbing at the helper level."""
    newer = os.path.join(state_dir, "newer.sapmap")
    older = os.path.join(state_dir, "older.sapmap")
    with open(older, "w", encoding="utf-8") as f:
        json.dump({"snc_credentials": {"X": {}}, "forged_tickets": []}, f)
    with open(newer, "w", encoding="utf-8") as f:
        json.dump({"snc_credentials": {}, "forged_tickets": []}, f)
    # Advance mtime so `newer` is unambiguously the most-recent.
    os.utime(newer, (os.path.getmtime(older) + 10,
                     os.path.getmtime(older) + 10))

    # Excluding `newer` should hand back `older`, not newer itself.
    picked = _state_mod._most_recent_autosave(state_dir, exclude_path=newer)
    assert picked == os.path.abspath(older)

    # Excluding `older` should hand back `newer`.
    picked = _state_mod._most_recent_autosave(state_dir, exclude_path=older)
    assert picked == os.path.abspath(newer)

    # Excluding nothing should hand back whichever is newest.
    picked = _state_mod._most_recent_autosave(state_dir, exclude_path="")
    assert picked == os.path.abspath(newer)


def test_overwrite_same_path_detects_regression(state_dir, capsys):
    """Operator-named 'Save As' repeatedly overwrites the SAME file.
    When the second save of that file has lost the wallet, the detector
    must still fire — pinned by exclude_path falling back to the older
    sibling autosave rather than mis-reading the file we're overwriting.
    """
    s = _populated_state()
    pinned = os.path.join(state_dir, "pinned.sapmap")
    # First autosave — populated.  Write an EARLIER sibling first so the
    # detector has a reference even when the pinned path itself is the
    # most-recent file after step 1 lands.
    save_state(s, os.path.join(state_dir, "sibling.sapmap"))
    save_state(s, pinned)

    # Wipe wallet, re-save to the SAME pinned path.
    s.snc_credentials.clear()
    save_state(s, pinned)

    # A trace file must have landed beside the pinned save.
    traces = [t for t in os.listdir(state_dir)
              if t.startswith("pinned.sapmap.WIPE_TRACE_")]
    assert len(traces) >= 1, f"expected a WIPE_TRACE beside pinned save, got {os.listdir(state_dir)}"


def test_tracked_counts_schema_variants():
    """The helper must handle every variant to_dict() emits: a wallet
    dict with N entries, an empty dict, a missing key, and a non-dict
    garbage value.  Prevents the detector from exploding on a corrupt
    or partially-written .sapmap and silently dropping the save."""
    from sapmap_state import _tracked_field_counts
    assert _tracked_field_counts({"snc_credentials": {"A": {}, "B": {}},
                                  "forged_tickets": [{}]}) == {
        "snc_credentials": 2, "forged_tickets": 1,
    }
    assert _tracked_field_counts({}) == {"snc_credentials": 0,
                                         "forged_tickets": 0}
    # A non-dict/list value must coerce to 0, not raise.
    assert _tracked_field_counts({"snc_credentials": "bogus",
                                  "forged_tickets": None}) == {
        "snc_credentials": 0, "forged_tickets": 0,
    }
