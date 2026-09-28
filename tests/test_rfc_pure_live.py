"""Live integration tests for the pure-Python RFC backend (sap_rfc_pure).

These talk to a real SAP system and are SKIPPED unless you opt in:

    export SAPMAP_LIVE_RFC=1
    export SAPMAP_RFC_ASHOST=192.168.2.209
    export SAPMAP_RFC_SYSNR=00
    export SAPMAP_RFC_CLIENT=001
    export SAPMAP_RFC_USER=DDIC
    export SAPMAP_RFC_PASSWD=******
    # optional, to reach the target through a SAProuter:
    export SAPMAP_RFC_SAPROUTER=/H/192.168.2.209/S/3299
    pytest tests/test_rfc_pure_live.py -v

They exercise the authenticated surface SAPMAP layers on the adapter and,
crucially, the two conditions that used to need adapter workarounds:
  * #24 — a call carrying an extra kwarg not in the FM interface succeeds.
  * #30 — an ABAP payload > 64KB encodes without a frame-footer overflow.

Set SAPMAP_RFC_DIFF_CSDK=1 (with the C SDK + pyrfc installed) to also run
the differential parity check: the same operations through both backends
must return equal results.
"""
import os

import pytest

saprfclib = pytest.importorskip("saprfclib")

import sap_rfc_pure as P  # noqa: E402

LIVE = os.getenv("SAPMAP_LIVE_RFC") == "1"
pytestmark = pytest.mark.skipif(
    not LIVE,
    reason="set SAPMAP_LIVE_RFC=1 and SAPMAP_RFC_* env vars to run live tests",
)


def _conn_params():
    missing = [v for v in ("SAPMAP_RFC_ASHOST", "SAPMAP_RFC_SYSNR",
                           "SAPMAP_RFC_CLIENT", "SAPMAP_RFC_USER",
                           "SAPMAP_RFC_PASSWD")
               if not os.getenv(v)]
    if missing:
        pytest.skip(f"missing env vars: {', '.join(missing)}")
    params = dict(
        ashost=os.environ["SAPMAP_RFC_ASHOST"],
        sysnr=os.environ["SAPMAP_RFC_SYSNR"],
        client=os.environ["SAPMAP_RFC_CLIENT"],
        user=os.environ["SAPMAP_RFC_USER"],
        passwd=os.environ["SAPMAP_RFC_PASSWD"],
    )
    router = os.getenv("SAPMAP_RFC_SAPROUTER")
    if router:
        params["saprouter"] = router
    return params


@pytest.fixture
def pure_conn():
    conn = P.RFCConnection(**_conn_params())
    conn.open()
    yield conn
    conn.close()


def _read_table(conn, table, fields, rowcount=5, options=None):
    """RFC_READ_TABLE through the manually-built descriptor path (call_raw),
    exactly as sapmap_rfc.py drives it — this exercises _make_func_desc /
    _make_type_desc against a real server."""
    fields_td = conn._make_type_desc("RFC_DB_FLD", [
        ("FIELDNAME", P.RFCTYPE_CHAR, 30, 60),
        ("FIELDTEXT", P.RFCTYPE_CHAR, 60, 120),
        ("TYPE",      P.RFCTYPE_CHAR, 1, 2),
        ("LENGTH",    P.RFCTYPE_CHAR, 6, 12),
        ("OFFSET",    P.RFCTYPE_CHAR, 6, 12),
    ])
    options_td = conn._make_type_desc("RFC_DB_OPT", [("TEXT", P.RFCTYPE_CHAR, 72, 144)])
    data_td = conn._make_type_desc("TAB512", [("WA", P.RFCTYPE_CHAR, 512, 1024)])
    fdesc = conn._make_func_desc("RFC_READ_TABLE", [
        ("QUERY_TABLE", P.RFC_IMPORT, P.RFCTYPE_CHAR,  60,  30,  None),
        ("DELIMITER",   P.RFC_IMPORT, P.RFCTYPE_CHAR,  2,   1,   None),
        ("ROWCOUNT",    P.RFC_IMPORT, P.RFCTYPE_INT,   4,   4,   None),
        ("FIELDS",      P.RFC_TABLES, P.RFCTYPE_TABLE, 206, 103, fields_td),
        ("OPTIONS",     P.RFC_TABLES, P.RFCTYPE_TABLE, 144, 72,  options_td),
        ("DATA",        P.RFC_TABLES, P.RFCTYPE_TABLE, 1024, 512, data_td),
    ])
    kwargs = dict(QUERY_TABLE=table, DELIMITER="|", ROWCOUNT=rowcount,
                  FIELDS=[{"FIELDNAME": f} for f in fields])
    if options:
        kwargs["OPTIONS"] = [{"TEXT": o} for o in options]
    return conn.call_raw("RFC_READ_TABLE", fdesc, **kwargs)


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------

def test_ping(pure_conn):
    assert pure_conn.ping() in (True, None) or pure_conn.is_open


def test_get_attributes(pure_conn):
    attrs = pure_conn.get_attributes()
    assert isinstance(attrs, dict)
    # at least the system id / host should come back
    assert any(attrs.get(k) for k in ("sysId", "partnerHost", "host"))


# ---------------------------------------------------------------------------
# Authenticated surface
# ---------------------------------------------------------------------------

def test_rfc_read_table_t000(pure_conn):
    """T000 (clients) via the call_raw descriptor path."""
    res = _read_table(pure_conn, "T000", ["MANDT", "MTEXT", "ORT01"])
    rows = res.get("DATA", [])
    assert rows, "expected at least one client row"
    assert "|" in rows[0]["WA"]


def test_bapi_user_get_detail(pure_conn):
    """A BAPI returning both a structure (ADDRESS) and tables (PROFILES)."""
    res = pure_conn.call("BAPI_USER_GET_DETAIL",
                         USERNAME=os.environ["SAPMAP_RFC_USER"])
    assert isinstance(res, dict)
    assert "ADDRESS" in res or "PROFILES" in res


# ---------------------------------------------------------------------------
# The two conditions that used to need adapter workarounds
# ---------------------------------------------------------------------------

def test_unknown_kwarg_is_dropped_live(pure_conn):
    """#24: an extra kwarg not in the FM interface must not raise —
    saprfclib drops it (strict_params=False)."""
    baseline = _read_table(pure_conn, "T000", ["MANDT"])
    # add a bogus param to the RFC_READ_TABLE call
    fdesc = pure_conn._make_func_desc("RFC_READ_TABLE", [
        ("QUERY_TABLE", P.RFC_IMPORT, P.RFCTYPE_CHAR, 60, 30, None),
    ])
    res = pure_conn.call_raw("RFC_READ_TABLE", fdesc,
                             QUERY_TABLE="T000",
                             ROWCOUNT=1,
                             THIS_PARAM_DOES_NOT_EXIST="ignored")
    assert isinstance(res, dict)  # completed, extra param ignored


def test_abap_install_and_run_over_64kb_no_footer_overflow(pure_conn):
    """#30: a > 64KB ABAP report body must encode without a TLV frame-footer
    overflow.  We only assert the *encoding* survives — an authorization
    failure (missing S_DEVELOP) is acceptable, a struct/64KB error is not."""
    filler = "\n".join(f"* padding line {i:06d}" for i in range(3000))  # ~60KB+
    assert len(filler.encode()) > 64 * 1024
    program = [
        {"LINE": "REPORT ZSAPMAP_TEST."},
        {"LINE": filler},
        {"LINE": "WRITE: / 'sapmap-64k-ok'."},
    ]
    try:
        res = pure_conn.call("RFC_ABAP_INSTALL_AND_RUN", PROGRAM=program)
    except P.RFCError as e:
        # A clean ABAP/authorization error is fine; a 64KB/struct overflow is not.
        assert "64KB" not in str(e) and "struct" not in str(e).lower(), \
            f"frame-footer overflow regressed: {e}"
        return
    lines = [r.get("LINE", "") for r in res.get("WRITES", [])]
    assert any("sapmap-64k-ok" in ln for ln in lines)


# ---------------------------------------------------------------------------
# Differential parity: pure backend vs the C SDK (opt-in)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.getenv("SAPMAP_RFC_DIFF_CSDK") != "1",
                    reason="set SAPMAP_RFC_DIFF_CSDK=1 (with C SDK + pyrfc) for parity check")
def test_read_table_parity_pure_vs_csdk():
    """The same RFC_READ_TABLE must return equal rows through both backends —
    the definitive proof that the pure adapter is a drop-in replacement."""
    import sap_rfc_ctypes as C

    params = _conn_params()
    with P.RFCConnection(**params) as pure, C.RFCConnection(**params) as csdk:
        pure.open(); csdk.open()
        pure_rows = _read_table(pure, "T000", ["MANDT", "MTEXT"])["DATA"]
        csdk_rows = _read_table(csdk, "T000", ["MANDT", "MTEXT"])["DATA"]
    assert [r["WA"] for r in pure_rows] == [r["WA"] for r in csdk_rows]
