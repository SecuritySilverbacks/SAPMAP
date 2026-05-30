"""Unit tests for modules.exploitation.sap_transport_import.

Focused on the things we can test without hitting a live SAP host —
the zip parser, the tp returncode extractor, and the capability/
catalogue wiring.  The network-level flow against S4H@192.168.2.209
is exercised by hand against the lab.
"""
import io
import zipfile

import pytest

import sap_transport_import as ti
import sapmap_attack


# ---------------------------------------------------------------------------
# parse_transport_zip
# ---------------------------------------------------------------------------

def _make_zip(*members):
    """members: iterable of (filename, bytes)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def test_parse_valid_pair():
    z = _make_zip(
        ("K900111.A4H", b"COFILE-MARKER"),
        ("R900111.A4H", b"DATAFILE-MARKER"),
    )
    meta = ti.parse_transport_zip(z)
    assert meta["source_sid"] == "A4H"
    assert meta["transport_num"] == "900111"
    assert meta["trkorr"] == "A4HK900111"
    assert meta["cofile_bytes"] == b"COFILE-MARKER"
    assert meta["datafile_bytes"] == b"DATAFILE-MARKER"


def test_parse_strips_leading_directories():
    """Some operators zip the files from /usr/sap/trans/ paths; the
    parser must walk to the basename of each entry."""
    z = _make_zip(
        ("trans/cofiles/K900222.S4H", b"x"),
        ("trans/data/R900222.S4H",    b"y"),
    )
    meta = ti.parse_transport_zip(z)
    assert meta["trkorr"] == "S4HK900222"


def test_parse_rejects_missing_cofile():
    z = _make_zip(("R900111.A4H", b"x"))
    with pytest.raises(ValueError, match="exactly ONE K"):
        ti.parse_transport_zip(z)


def test_parse_rejects_mismatched_pair():
    z = _make_zip(
        ("K900111.A4H", b"x"),
        ("R900222.A4H", b"y"),    # different transport number
    )
    with pytest.raises(ValueError, match="same number"):
        ti.parse_transport_zip(z)


def test_parse_rejects_mismatched_sid():
    z = _make_zip(
        ("K900111.A4H", b"x"),
        ("R900111.S4H", b"y"),
    )
    with pytest.raises(ValueError, match="same number"):
        ti.parse_transport_zip(z)


def test_parse_rejects_multiple_cofiles():
    z = _make_zip(
        ("K900111.A4H", b"x"),
        ("K900222.A4H", b"x"),
        ("R900111.A4H", b"y"),
    )
    with pytest.raises(ValueError, match="exactly ONE"):
        ti.parse_transport_zip(z)


def test_parse_rejects_garbage_zip():
    with pytest.raises(ValueError, match="not a valid zip"):
        ti.parse_transport_zip(b"not a zip")


# ---------------------------------------------------------------------------
# tp returncode parser (extracted via _run_tp -> output)
# ---------------------------------------------------------------------------

def test_tp_rc_regex_finds_zero():
    out = [
        "This is tp version 381.584.54 (release 793, unicode enabled)",
        "Addtobuffer successful for A4HK900111",
        "tp finished with return code: 0",
        "tp call duration was: 0.013551 sec",
    ]
    rc = None
    for line in reversed(out):
        m = ti._TP_RC_RE.search(line)
        if m:
            rc = int(m.group(1))
            break
    assert rc == 0


def test_tp_rc_regex_finds_nonzero():
    out = [
        "ERROR: too many arguments",
        "tp finished with return code: 203",
    ]
    rc = None
    for line in reversed(out):
        m = ti._TP_RC_RE.search(line)
        if m:
            rc = int(m.group(1))
            break
    assert rc == 203


# ---------------------------------------------------------------------------
# Progress dict lifecycle
# ---------------------------------------------------------------------------

def test_progress_setter_records_updates():
    setp = ti._new_progress("test_task_xyz")
    setp(phase="upload_cofile", message="hi", percent=50, current=5, total=10)
    p = ti.get_progress("test_task_xyz")
    assert p["phase"] == "upload_cofile"
    assert p["percent"] == 50
    assert p["current"] == 5
    assert p["total"] == 10
    ti.clear_progress("test_task_xyz")
    assert ti.get_progress("test_task_xyz") == {}


def test_progress_log_appends_and_caps():
    setp = ti._new_progress("test_log_cap")
    for i in range(250):
        setp(log_line=f"line {i}")
    p = ti.get_progress("test_log_cap")
    assert len(p["log"]) == 200
    assert p["log"][-1] == "line 249"
    ti.clear_progress("test_log_cap")


def test_unknown_task_id_returns_empty():
    assert ti.get_progress("nope_doesnt_exist_xyz") == {}


# ---------------------------------------------------------------------------
# ATT&CK catalog wiring
# ---------------------------------------------------------------------------

def test_capability_keys_registered():
    assert "persist.transport_addtobuffer" in sapmap_attack.CAPABILITY_MAP
    assert "persist.transport_import" in sapmap_attack.CAPABILITY_MAP


def test_capability_techniques_resolve():
    for key in ("persist.transport_addtobuffer", "persist.transport_import"):
        for tid in sapmap_attack.CAPABILITY_MAP[key]:
            assert sapmap_attack.lookup(tid) is not None, \
                f"{key} → {tid} doesn't resolve"


def test_transport_import_includes_t1059_t1505_t1098():
    """The full import IS code execution + new server software + role
    manipulation — heatmap must reflect all three.  Test pins this
    convention so a future contributor doesn't drop one."""
    tids = set(sapmap_attack.CAPABILITY_MAP["persist.transport_import"])
    assert "T1505" in tids
    assert "T1059" in tids
    assert "T1098" in tids


def test_transport_addtobuffer_excludes_t1059():
    """addtobuffer only stages — no code runs yet, so we should NOT
    light up Execution at this stage."""
    tids = set(sapmap_attack.CAPABILITY_MAP["persist.transport_addtobuffer"])
    assert "T1059" not in tids


# ---------------------------------------------------------------------------
# Post-verify regex — recover from SAPXPG P4 output truncation
# ---------------------------------------------------------------------------

def test_buffer_ok_regex_matches_completed_imports():
    """tp showbuffer prints 'has already been imported completely' when
    the transport landed cleanly — the rc=None fallback uses this
    keyword to recover the actual return code."""
    line = "| A4HK900111          |                    | |has already been imported completely."
    assert ti._TP_BUFFER_OK_RE.search(line) is not None


def test_buffer_ok_regex_matches_in_progress_imports():
    """An import that's still running shouldn't be classified as a failure."""
    line = "| A4HK900112  | is currently being imported"
    assert ti._TP_BUFFER_OK_RE.search(line) is not None


def test_buffer_ok_regex_matches_zero_step_status():
    """Each tp step prints its rc in *NNNN format — *0000 means OK."""
    line = "| A4HK900113          |          | |*0000 |*0000 |"
    assert ti._TP_BUFFER_OK_RE.search(line) is not None


# ---------------------------------------------------------------------------
# OS-aware path resolution
# ---------------------------------------------------------------------------

class _MockNode:
    def __init__(self, sid: str, os_type: str = ""):
        self.sid = sid
        self.os_type = os_type
        self.system_type = "ABAP"


def test_resolve_paths_linux_default():
    p = ti._resolve_paths(_MockNode("S4H", "Linux/Unix"))
    assert p["cofiles_dir"] == "/usr/sap/trans/cofiles"
    assert p["data_dir"]    == "/usr/sap/trans/data"
    assert p["pfl"]         == "/usr/sap/trans/bin/TP_DOMAIN_S4H.PFL"
    assert p["sep"]         == "/"


def test_resolve_paths_windows():
    p = ti._resolve_paths(_MockNode("TWT", "Windows"))
    assert p["cofiles_dir"] == r"C:\usr\sap\trans\cofiles"
    assert p["data_dir"]    == r"C:\usr\sap\trans\data"
    assert p["pfl"]         == r"C:\usr\sap\trans\bin\TP_DOMAIN_TWT.PFL"
    assert p["sep"]         == "\\"


def test_resolve_paths_blank_os_defaults_linux():
    """Defensive: blank os_type → Linux path layout (most SAP systems
    in the wild)."""
    p = ti._resolve_paths(_MockNode("XYZ", ""))
    assert "/usr/sap/trans" in p["trans_dir"]


def test_os_type_detection():
    assert ti._os_type(_MockNode("a", "Windows NT")) == "windows"
    assert ti._os_type(_MockNode("a", "Windows Server 2019")) == "windows"
    assert ti._os_type(_MockNode("a", "Linux/Unix")) == "linux"
    assert ti._os_type(_MockNode("a", "AIX")) == "linux"  # not windows
    assert ti._os_type(_MockNode("a", "")) == "linux"     # default
