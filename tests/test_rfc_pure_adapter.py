"""Offline tests for the pure-Python RFC backend adapter (sap_rfc_pure).

No SAP system required — saprfclib's own encoders/metadata helpers and a
fake in-memory Connection cover:

  * Regression guards for the two upstream fixes that let the adapter drop
    its workarounds (saprfclib #24 unknown-kwarg parity, #30 the >64KB TLV
    frame footer).  If a future saprfclib regresses either, these fail in CI
    instead of silently at runtime against a live box.
  * Adapter behaviour: result normalization, exception translation, kwarg
    passthrough, connect() param mapping, connection lifecycle.
  * The manually-built type/function descriptors (_make_type_desc /
    _make_func_desc) that call_raw() callers rely on — these track
    saprfclib's FieldDesc/TypeDesc constructor, which changed between 0.1.1
    and 0.1.5.

Live end-to-end coverage lives in test_rfc_pure_live.py (env-gated).
"""
import datetime
import inspect
import struct

import pytest

# saprfclib requires Python 3.12+; skip the whole module cleanly otherwise.
saprfclib = pytest.importorskip("saprfclib")

import sap_rfc_pure as P  # noqa: E402  (conftest registers modules/* on sys.path)


# ---------------------------------------------------------------------------
# Fake saprfclib Connection — records calls, returns canned results
# ---------------------------------------------------------------------------

class FakeConn:
    def __init__(self, result=None, raises=None):
        self._result = result if result is not None else {}
        self._raises = raises
        self.calls = []
        self.closed = False
        self.ping_ok = True

    def call(self, func_name, **kwargs):
        self.calls.append((func_name, kwargs))
        if self._raises is not None:
            raise self._raises
        return self._result

    def ping(self):
        return self.ping_ok

    def close(self):
        self.closed = True


@pytest.fixture
def open_conn(monkeypatch):
    """Return a factory: fake -> an opened P.RFCConnection wrapping it."""
    def _factory(fake):
        monkeypatch.setattr(P._lib, "connect", lambda **kw: fake)
        conn = P.RFCConnection(ashost="h", sysnr="00", client="000")
        conn.open()
        return conn
    return _factory


# ---------------------------------------------------------------------------
# Regression guards for the removed workarounds (the heart of issue #39)
# ---------------------------------------------------------------------------

def test_connect_defaults_to_lenient_strict_params():
    """#24: connect()/Connection default strict_params=False, so unknown
    kwargs are dropped like pyrfc / the C SDK.  The adapter relies on this
    instead of its old catch-ValueError-and-retry workaround."""
    sig = inspect.signature(saprfclib.connect).parameters
    assert "strict_params" in sig
    assert sig["strict_params"].default is False

    from saprfclib.connection import Connection
    csig = inspect.signature(Connection.__init__).parameters
    assert csig["strict_params"].default is False


def test_unknown_kwargs_are_dropped_by_lib():
    """#24: saprfclib itself now filters unknown params against the interface."""
    from saprfclib.invoke import unknown_parameters, drop_unknown_parameters

    conn = P.RFCConnection(ashost="h", sysnr="00", client="000")
    desc = conn._make_func_desc("Z_DEMO", [
        ("REAL_PARAM", P.RFC_IMPORT, P.RFCTYPE_CHAR, 2, 1, None),
    ])
    params = {"REAL_PARAM": "x", "BOGUS": "y"}
    assert unknown_parameters(desc, params) == ["BOGUS"]
    assert drop_unknown_parameters(desc, params) == {"REAL_PARAM": "x"}


def test_tlv_record_large_body_uses_extended_uint32_length():
    """#30: bodies >= 64KB encode via the extended uint32 length form, so
    large ABAP INSTALL_AND_RUN payloads no longer overflow the 16-bit footer
    (the struct.error the adapter used to catch)."""
    from saprfclib.invoke import tlv_record

    body = b"A" * 70000
    rec = tlv_record(0x0303, body)          # must not raise struct.error
    assert rec[2:4] == b"\xff\xff"
    assert struct.unpack(">I", rec[4:8])[0] == 70000


@pytest.mark.parametrize("size,extended", [
    (0xFFFE, False),   # 65534 — normal 16-bit length
    (0xFFFF, True),    # 65535 — switch to extended
    (0x10000, True),   # 65536 — extended
])
def test_tlv_record_length_switch_boundary(size, extended):
    from saprfclib.invoke import tlv_record

    rec = tlv_record(0x0303, b"A" * size)
    if extended:
        assert rec[2:4] == b"\xff\xff"
        assert struct.unpack(">I", rec[4:8])[0] == size
    else:
        assert struct.unpack(">H", rec[2:4])[0] == size


def test_saprfclib_meets_min_version():
    """requirements.txt pins >= 0.1.5 (the release carrying #24 and #30).
    Fail loudly on an under-pinned environment rather than hitting the old
    ValueError / struct.error behaviour at runtime."""
    parts = tuple(int(x) for x in saprfclib.__version__.split(".")[:3])
    assert parts >= (0, 1, 5), f"saprfclib {saprfclib.__version__} < 0.1.5"


# ---------------------------------------------------------------------------
# Adapter behaviour
# ---------------------------------------------------------------------------

def test_call_normalizes_date_and_time_to_strings(open_conn):
    """C SDK returns raw YYYYMMDD / HHMMSS strings; saprfclib returns
    date/time objects.  The adapter must convert back, recursively."""
    conn = open_conn(FakeConn(result={
        "ERFDAT": datetime.date(2026, 9, 26),
        "ERFTIME": datetime.time(13, 5, 0),
        "TABLE": [{"D": datetime.date(2026, 1, 2)}],
    }))
    out = conn.call("ANY_FM")
    assert out["ERFDAT"] == "20260926"
    assert out["ERFTIME"] == "130500"
    assert out["TABLE"][0]["D"] == "20260102"


def test_call_forwards_all_kwargs_to_lib(open_conn):
    """The adapter no longer pre-filters kwargs — saprfclib's strict_params
    policy owns that now — so everything passes straight through."""
    fake = FakeConn(result={"ok": 1})
    conn = open_conn(fake)
    conn.call("RFC_READ_TABLE", QUERY_TABLE="T000", EXTRA="keepme")
    assert fake.calls == [("RFC_READ_TABLE",
                           {"QUERY_TABLE": "T000", "EXTRA": "keepme"})]


@pytest.mark.parametrize("exc_factory,expected", [
    (lambda: saprfclib.AbapApplicationError(message="boom", key="RFC_ERROR"),
     "ABAPApplicationError"),
    (lambda: saprfclib.CommunicationError("reset"), "CommunicationError"),
    (lambda: saprfclib.AbapSystemFailure(message="dump"), "ABAPRuntimeError"),
    (lambda: saprfclib.SapRfcError("generic"), "RFCError"),
])
def test_call_translates_saprfclib_exceptions(open_conn, exc_factory, expected):
    conn = open_conn(FakeConn(raises=exc_factory()))
    with pytest.raises(getattr(P, expected)):
        conn.call("ANY_FM")


def test_call_wraps_generic_exception_as_rfcerror(open_conn):
    conn = open_conn(FakeConn(raises=RuntimeError("weird")))
    with pytest.raises(P.RFCError):
        conn.call("ANY_FM")


def test_call_before_open_raises_rfcerror():
    conn = P.RFCConnection(ashost="h", sysnr="00", client="000")
    with pytest.raises(P.RFCError):
        conn.call("ANY_FM")


def test_connect_param_mapping(monkeypatch):
    """sysnr str -> int; unsupported kwargs dropped; sdk_path ignored."""
    captured = {}

    def fake_connect(**kw):
        captured.update(kw)
        return FakeConn()

    monkeypatch.setattr(P._lib, "connect", fake_connect)
    conn = P.RFCConnection(sdk_path="/opt/nwrfcsdk", ashost="h", sysnr="02",
                           client="000", user="U", passwd="P",
                           not_a_real_kwarg=123)
    conn.open()
    assert captured["sysnr"] == 2               # coerced str -> int
    assert "not_a_real_kwarg" not in captured   # unsupported dropped
    assert "sdk_path" not in captured           # never forwarded


def test_open_is_idempotent_and_context_manager(monkeypatch):
    fake = FakeConn()
    connects = []
    monkeypatch.setattr(P._lib, "connect",
                        lambda **kw: connects.append(kw) or fake)
    with P.RFCConnection(ashost="h", sysnr="00", client="000") as conn:
        conn.open()  # second open() must not reconnect
        assert conn.is_open is True
    assert len(connects) == 1
    assert fake.closed is True


def test_is_open_reflects_ping(open_conn):
    fake = FakeConn()
    conn = open_conn(fake)
    assert conn.is_open is True
    fake.ping_ok = False
    assert conn.is_open is False


# ---------------------------------------------------------------------------
# Manually-built descriptors (guards the FieldDesc/TypeDesc API that changed
# between saprfclib 0.1.1 and 0.1.5 — call_raw callers in sapmap_rfc /
# sapmap_lpe build these before every fallback call).
# ---------------------------------------------------------------------------

def test_make_type_desc_builds_cumulative_offsets():
    conn = P.RFCConnection(ashost="h", sysnr="00", client="000")
    td = conn._make_type_desc("RFC_DB_FLD", [
        ("FIELDNAME", P.RFCTYPE_CHAR, 30, 60),
        ("TYPE",      P.RFCTYPE_CHAR, 1, 2),
    ])
    assert td.name == "RFC_DB_FLD"
    assert [f.rfctype for f in td.fields] == [P.RFCTYPE_CHAR, P.RFCTYPE_CHAR]
    # offsets accumulate across fields (nuc then uc)
    assert td.fields[0].nuc_offset == 0 and td.fields[1].nuc_offset == 30
    assert td.fields[0].uc_offset == 0 and td.fields[1].uc_offset == 60


def test_make_func_desc_matches_rfc_read_table_shape():
    """Reproduces the real RFC_READ_TABLE descriptor built in sapmap_rfc.py;
    must construct against the installed saprfclib without raising."""
    conn = P.RFCConnection(ashost="h", sysnr="00", client="000")
    fields_td = conn._make_type_desc("RFC_DB_FLD", [
        ("FIELDNAME", P.RFCTYPE_CHAR, 30, 60),
    ])
    data_td = conn._make_type_desc("TAB512", [("WA", P.RFCTYPE_CHAR, 512, 1024)])
    fdesc = conn._make_func_desc("RFC_READ_TABLE", [
        ("QUERY_TABLE", P.RFC_IMPORT, P.RFCTYPE_CHAR,  60,  30,  None),
        ("ROWCOUNT",    P.RFC_IMPORT, P.RFCTYPE_INT,   4,   4,   None),
        ("FIELDS",      P.RFC_TABLES, P.RFCTYPE_TABLE, 206, 103, fields_td),
        ("DATA",        P.RFC_TABLES, P.RFCTYPE_TABLE, 1024, 512, data_td),
    ])
    assert fdesc.name == "RFC_READ_TABLE"
    assert len(fdesc.parameters) == 4
    fields = fdesc.parameters[2]
    assert fields.direction == P.RFC_TABLES        # numeric direction, not a string
    assert fields.rfctype == P.RFCTYPE_TABLE
    assert fields.type_desc is fields_td           # linked type descriptor
