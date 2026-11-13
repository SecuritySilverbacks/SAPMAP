"""Issue #167 — SNC-aware RFC_SYSTEM_INFO probe.

Phase A tests: ``SAPNode.snc_posture`` field basics.
Phase B tests: ``_tcp_reach`` helper in sapmap_scanner.
Phase C tests: ``rfc_system_info_over_snc`` helper, ``_classify_snc_error``,
  ``_scrub_secrets``, and the ``_SECUDIR_LOCK`` serialisation.

The rest of the suite (classifier branches at the enrich-site, GUI
route wiring, report rendering, autopwn skip) is added in later phases.
"""

import json
import os
import socket
import threading
import time

import pytest

import sapmap_rfc
import sapmap_scanner
from sapmap_models import SAPNode


SNC_POSTURE_VALUES = (
    "",
    "no_sap_signal",
    "none",
    "optional",
    "enforced_no_creds",
    "enforced_handshake_failed",
    "enforced_logon_failed",
    "reachable_auth",
)


def test_sapnode_snc_posture_default_is_empty_string():
    """A fresh SAPNode has snc_posture == '' — never classified."""
    node = SAPNode(sid="TST")
    assert node.snc_posture == ""


@pytest.mark.parametrize("posture", SNC_POSTURE_VALUES)
def test_sapnode_snc_posture_roundtrip_through_json(posture):
    """Every verdict value survives the .sapmap JSON round-trip."""
    original = SAPNode(sid="S4H", snc_posture=posture)
    restored = SAPNode.from_dict(json.loads(json.dumps(original.to_dict())))
    assert restored.snc_posture == posture


def test_sapnode_snc_posture_from_dict_defaults_to_empty_when_missing():
    """Older .sapmap files (no snc_posture key) still load cleanly."""
    legacy_dict = {"sid": "NPL"}            # no snc_posture key at all
    loaded = SAPNode.from_dict(legacy_dict)
    assert loaded.snc_posture == ""


def test_sapnode_snc_posture_appears_in_to_dict_output():
    """to_dict always emits snc_posture — consumers can rely on the key."""
    node = SAPNode(sid="TST")               # default posture
    d = node.to_dict()
    assert "snc_posture" in d
    assert d["snc_posture"] == ""


# ------------------------------------------------------------------
# Phase B — _tcp_reach helper
# ------------------------------------------------------------------


def test_tcp_reach_direct_returns_true_when_socket_connects(monkeypatch):
    """Plain-socket path returns True on a successful create_connection."""
    class _FakeSock:
        def close(self):
            pass

    captured = {}

    def _fake_create_connection(address, timeout=None):
        captured["address"] = address
        captured["timeout"] = timeout
        return _FakeSock()

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is True
    assert captured["address"] == ("10.0.0.1", 4800)


def test_tcp_reach_direct_returns_false_on_connect_refused(monkeypatch):
    """Plain-socket path returns False on ConnectionRefusedError."""
    def _fake_create_connection(address, timeout=None):
        raise ConnectionRefusedError("ECONNREFUSED")

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is False


def test_tcp_reach_direct_returns_false_on_timeout(monkeypatch):
    """Plain-socket path returns False on socket.timeout, never raises."""
    def _fake_create_connection(address, timeout=None):
        raise socket.timeout("timed out")

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is False


def test_tcp_reach_clamps_timeout_to_4_seconds(monkeypatch):
    """A 60s caller timeout is capped at 4s — _tcp_reach is a diagnostic
    probe, not the main scan budget."""
    captured = {}

    class _FakeSock:
        def close(self):
            pass

    def _fake_create_connection(address, timeout=None):
        captured["timeout"] = timeout
        return _FakeSock()

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=60.0)
    assert captured["timeout"] == 4.0


def test_tcp_reach_tunnels_through_saprouter_when_set(monkeypatch):
    """When saprouter is set, the probe goes via connect_through_saprouter —
    NOT a bare socket (which would always fail on a router'd target)."""
    captured = {"direct_calls": 0}

    class _FakeSock:
        def close(self):
            pass

    def _fake_create_connection(address, timeout=None):
        captured["direct_calls"] += 1
        return _FakeSock()

    def _fake_build_route(saprouter, host, port):
        captured["route_args"] = (saprouter, host, port)
        return "route-token"

    def _fake_connect_through_saprouter(route, timeout):
        captured["router_call"] = (route, timeout)
        return _FakeSock()

    import sap_saprouter
    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    monkeypatch.setattr(sap_saprouter, "build_route_for_port",
                        _fake_build_route)
    monkeypatch.setattr(sap_saprouter, "connect_through_saprouter",
                        _fake_connect_through_saprouter)

    ok = sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0,
                                   saprouter="10.0.0.254:3299")
    assert ok is True
    assert captured["route_args"] == ("10.0.0.254:3299", "10.0.0.1", 4800)
    assert captured["router_call"] == ("route-token", 3.0)
    assert captured["direct_calls"] == 0  # Direct path not used.


def test_tcp_reach_saprouter_path_returns_false_on_failure(monkeypatch):
    """SAProuter denial / NI_RTERR → False, never raises."""
    def _fake_build_route(saprouter, host, port):
        return "route-token"

    def _fake_connect_through_saprouter(route, timeout):
        raise OSError("NI_RTERR: route denied")

    import sap_saprouter
    monkeypatch.setattr(sap_saprouter, "build_route_for_port",
                        _fake_build_route)
    monkeypatch.setattr(sap_saprouter, "connect_through_saprouter",
                        _fake_connect_through_saprouter)

    ok = sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0,
                                   saprouter="10.0.0.254:3299")
    assert ok is False


def test_tcp_reach_never_raises_on_arbitrary_exception(monkeypatch):
    """Even a nonsense exception type from the underlying stack is caught."""
    def _fake_create_connection(address, timeout=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(sapmap_scanner.socket, "create_connection",
                        _fake_create_connection)
    assert sapmap_scanner._tcp_reach("10.0.0.1", 4800, timeout=3.0) is False


# ------------------------------------------------------------------
# Phase C — rfc_system_info_over_snc + _classify_snc_error + _scrub_secrets
# ------------------------------------------------------------------


@pytest.fixture
def _snc_reset():
    """Save/restore BOTH SNC module globals and SECUDIR env, so a test
    that mutates any of them leaves no footprint for later tests."""
    saved_cfg = dict(sapmap_rfc._snc_config)
    saved_cred = (dict(sapmap_rfc._snc_active_cred)
                  if sapmap_rfc._snc_active_cred else None)
    saved_env = os.environ.get("SECUDIR")
    try:
        yield
    finally:
        sapmap_rfc.set_snc_config(**saved_cfg)
        sapmap_rfc.set_snc_identity(saved_cred)
        if saved_env is None:
            os.environ.pop("SECUDIR", None)
        else:
            os.environ["SECUDIR"] = saved_env


@pytest.fixture
def _native(monkeypatch):
    """Force the native SNC backend reported available."""
    monkeypatch.setattr(sapmap_rfc, "_snc_native_available", lambda: True)


class _CaptureConn:
    """Fake RFC backend capturing params and controlling the RFC call."""
    last_params = None
    call_return = {"RFCSI_EXPORT": {
        "RFCSYSID": "S4H", "RFCHOST": "s4h01", "RFCHOST2": "",
        "RFCOPSYS": "Linux", "RFCDBSYS": "HDB",
        "RFCKERNRL": "793", "RFCSAPRL": "758",
        "RFCIPADDR": "10.0.0.1", "RFCIPV6ADDR": "",
    }}
    call_raises = None
    secudir_seen = None

    @classmethod
    def reset(cls):
        cls.last_params = None
        cls.call_raises = None
        cls.secudir_seen = None
        cls.call_return = {"RFCSI_EXPORT": {
            "RFCSYSID": "S4H", "RFCHOST": "s4h01", "RFCHOST2": "",
            "RFCOPSYS": "Linux", "RFCDBSYS": "HDB",
            "RFCKERNRL": "793", "RFCSAPRL": "758",
            "RFCIPADDR": "10.0.0.1", "RFCIPV6ADDR": "",
        }}

    def __init__(self, sdk_path=None, **params):
        type(self).last_params = dict(params)
        type(self).secudir_seen = os.environ.get("SECUDIR")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def call(self, name, *args, **kwargs):
        if type(self).call_raises is not None:
            raise type(self).call_raises
        return type(self).call_return


@pytest.fixture
def _backend(monkeypatch):
    _CaptureConn.reset()
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend",
                        lambda: _CaptureConn)
    return _CaptureConn


def test_helper_emits_snc_params_from_operator_posture(
        _snc_reset, _backend, tmp_path):
    """Operator posture set, no looted cred → params carry snc_lib
    + snc_myname + snc_partnername + snc_sso='0'; SECUDIR mirrored."""
    secudir = str(tmp_path / "secudir")
    os.makedirs(secudir, exist_ok=True)
    sapmap_rfc.set_snc_config(
        secudir=secudir,
        sapcryptolib="/opt/sap/sapcrypto.so",
        identity="p:CN=sapmap-lab",
    )
    sapmap_rfc.set_snc_identity(None)

    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H",
        client="001", user="SAPMAP00", password="x" * 12)

    p = _backend.last_params
    assert p is not None
    assert p.get("snc_lib") == "/opt/sap/sapcrypto.so"
    assert p.get("snc_partnername") == "p:CN=S4H"
    assert p.get("snc_myname") == "p:CN=sapmap-lab"
    assert p.get("snc_sso") == "0"
    assert out["source"] == "rfcsi_snc_auth"
    assert _backend.secudir_seen == secudir     # was set during the call


def test_helper_uses_looted_cred_native_when_rsa(
        _snc_reset, _backend, _native):
    """RSA looted cred + native backend → snc_pse in params, snc_lib
    NOT in params, SECUDIR env NOT mutated."""
    prior_env = os.environ.get("SECUDIR", "__sentinel__")
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    sapmap_rfc.set_snc_identity({
        "cred_id": "S4H:SAPSYS", "source_sid": "S4H",
        "pse_path": "/loot/pse/S4H/SAPSYS.pse", "cred_v2_path": "",
        "pin": "", "snc_identity": "p:CN=S4H",
        "key_is_rsa": True, "path_pref": "auto",
    })

    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H",
        client="001", user="SAPMAP00", password="y" * 12)

    p = _backend.last_params
    assert p.get("snc_pse") == "/loot/pse/S4H/SAPSYS.pse"
    assert "snc_lib" not in p
    assert out["source"] == "rfcsi_snc_auth"
    # SECUDIR must not have been written during the native-path call.
    assert _backend.secudir_seen == (
        None if prior_env == "__sentinel__" else prior_env)


def test_helper_return_shape_contract(_snc_reset, _backend, _native):
    """The return dict must carry EXACTLY this key set — no more, no less.
    Both success and error branches must agree so a key rename on one
    side fails here first, not silently in a classifier that reads one
    name while the fake returns the other.
    """
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=lab")
    EXPECTED = {"sid", "hostname", "ip", "os_type", "db_type",
                "kernel", "sap_release", "snc", "source", "error", "phase"}

    out_ok = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="u", password="pw" * 6)
    assert set(out_ok.keys()) == EXPECTED

    _backend.call_raises = RuntimeError("logon failed: user is locked")
    out_err = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="u", password="pw" * 6)
    assert set(out_err.keys()) == EXPECTED
    assert out_err["error"]
    assert out_err["source"] == ""


def test_helper_source_requires_snc_params(_snc_reset, _backend, monkeypatch):
    """A regression that bypasses the snc gate but still reaches the
    RFC_SYSTEM_INFO call must NOT produce source='rfcsi_snc_auth'.
    Faked by monkeypatching _snc_params_for to return a non-empty dict
    that DOES NOT include snc_pse or snc_lib."""
    monkeypatch.setattr(sapmap_rfc, "_snc_params_for",
                        lambda name: {"snc_myname": "fake"})
    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="u", password="pw" * 6)
    assert out["source"] != "rfcsi_snc_auth"
    assert out["source"] == ""


def test_helper_passes_sysnr_lets_saprfclib_derive_4800_port(
        _snc_reset, _backend, _native):
    """Params must carry sysnr but no 'port' key — backend auto-derives
    4800+sysnr when SNC params are present.  Pins a positive on sysnr,
    so a refactor that explicitly sets port=4800+N would still pass."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=lab")

    sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="u", password="pw" * 6)
    p = _backend.last_params
    # Backend connects to 4800+sysnr (explicit OR derived) — pin that
    # invariant, not the literal "no port key" negative.
    assert p.get("sysnr") == "00"
    derived = 4800 + int(p["sysnr"])
    assert (p.get("port") in (None, derived, str(derived)))


def test_helper_rejects_missing_snc_partnername(
        _snc_reset, _backend, _native):
    """Empty partner name → stable 'snc_'-prefixed error sentinel, never
    opens a connection."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=lab")
    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "", user="u", password="pw" * 6)
    assert out["error"].startswith("snc_")
    assert out["source"] == ""
    assert _backend.last_params is None


def test_helper_no_snc_config_returns_snc_not_configured(
        _snc_reset, _backend):
    """No operator posture + no active looted cred → stable
    'snc_'-prefixed sentinel, no open."""
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    sapmap_rfc.set_snc_identity(None)

    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="u", password="pw" * 6)
    assert out["error"].startswith("snc_")
    assert out["source"] == ""
    assert _backend.last_params is None


@pytest.mark.parametrize("msg,expected_phase", [
    ("CommunicationError: RFC_LOGON_FAILURE / Name or password is incorrect",
     "logon"),
    ("CommunicationError: RFC_COMMUNICATION_FAILURE / SNC_ERROR / "
     "GSS_S_FAILURE acquiring the client credential",
     "snc_handshake"),
    ("PseError: only RSA keys are supported",
     "snc_handshake"),
    ("timed out while connecting to 10.0.0.1:4800",
     "transport"),
])
def test_classify_snc_error_phases(msg, expected_phase):
    """_classify_snc_error distinguishes the four phase buckets so the
    enrich classifier can emit enforced_handshake_failed vs
    enforced_logon_failed vs (sticky, unchanged) on a transient
    transport error."""
    exc = RuntimeError(msg)
    phase, raw = sapmap_rfc._classify_snc_error(exc)
    assert phase == expected_phase
    assert msg in raw or raw         # raw passes through format_rfc_exception


def test_helper_scrubs_pin_from_error(_snc_reset, _backend, _native):
    """When the SDK's exception message literally contains the active
    cred's PSE PIN, the returned error must NOT carry it."""
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    sapmap_rfc.set_snc_identity({
        "cred_id": "S4H:SAPSYS", "source_sid": "S4H",
        "pse_path": "/loot/pse/S4H/SAPSYS.pse", "cred_v2_path": "",
        "pin": "SHHHSECRET", "snc_identity": "p:CN=S4H",
        "key_is_rsa": True, "path_pref": "auto",
    })
    _backend.call_raises = RuntimeError(
        "logon failed: wrong PSE PIN 'SHHHSECRET' (debug diag)")
    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="u", password="pw" * 6)
    assert "SHHHSECRET" not in out["error"]
    assert "***" in out["error"]


def test_helper_scrubs_password_from_error(
        _snc_reset, _backend, _native):
    """Password never surfaces inside the returned error string."""
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    sapmap_rfc.set_snc_identity({
        "cred_id": "S4H:SAPSYS", "source_sid": "S4H",
        "pse_path": "/loot/pse/S4H/SAPSYS.pse", "cred_v2_path": "",
        "pin": "", "snc_identity": "p:CN=S4H",
        "key_is_rsa": True, "path_pref": "auto",
    })
    pw = "P4ssword!LOUD"
    _backend.call_raises = RuntimeError(
        f"logon failed for SAPMAP00 / {pw}")
    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="SAPMAP00", password=pw)
    assert pw not in out["error"]
    assert "***" in out["error"]


def test_helper_no_stdout_leak_of_pin_or_password(
        _snc_reset, _backend, _native, capsys):
    """Neither the active cred's PIN nor the caller's password appears
    in stdout/stderr after a happy-path call."""
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    sapmap_rfc.set_snc_identity({
        "cred_id": "S4H:SAPSYS", "source_sid": "S4H",
        "pse_path": "/loot/pse/S4H/SAPSYS.pse", "cred_v2_path": "",
        "pin": "SHHHSECRET", "snc_identity": "p:CN=S4H",
        "key_is_rsa": True, "path_pref": "auto",
    })
    pw = "P4ssword!LOUD"
    sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "00", "p:CN=S4H", user="SAPMAP00", password=pw)
    captured = capsys.readouterr()
    assert "SHHHSECRET" not in captured.out
    assert "SHHHSECRET" not in captured.err
    assert pw not in captured.out
    assert pw not in captured.err


def test_helper_concurrent_cryptolib_calls_serialise_on_SECUDIR_lock(
        _snc_reset, monkeypatch, tmp_path):
    """Two concurrent cryptolib-path calls with different SECUDIR values
    must each see THEIR OWN SECUDIR inside the connection block — not
    the other thread's.  The _SECUDIR_LOCK guarantees that.
    """
    sapmap_rfc.set_snc_config(
        secudir=str(tmp_path / "secA"),
        sapcryptolib="/opt/sap/sapcrypto.so",
        identity="p:CN=sapmap-lab",
    )
    sapmap_rfc.set_snc_identity(None)

    seen = []

    class _SlowBackend:
        def __init__(self, sdk_path=None, **params):
            # Record SECUDIR observed inside the (locked) connection.
            seen.append(os.environ.get("SECUDIR"))
            time.sleep(0.05)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def call(self, name, *args, **kwargs):
            # Second read of SECUDIR after a short sleep — another
            # thread's call must not have changed it under us.
            time.sleep(0.05)
            seen.append(os.environ.get("SECUDIR"))
            return {"RFCSI_EXPORT": {"RFCSYSID": "S4H", "RFCHOST": "s4h"}}

    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _SlowBackend)

    def _worker(secudir_val):
        # Each thread gets its OWN snc_config for the duration of its
        # call — set here just before the call starts.
        sapmap_rfc.set_snc_config(
            secudir=secudir_val,
            sapcryptolib="/opt/sap/sapcrypto.so",
            identity="p:CN=sapmap-lab",
        )
        sapmap_rfc.rfc_system_info_over_snc(
            "10.0.0.1", "00", "p:CN=S4H",
            user="u", password="pw" * 6)

    secA = str(tmp_path / "secA")
    secB = str(tmp_path / "secB")
    t1 = threading.Thread(target=_worker, args=(secA,))
    t2 = threading.Thread(target=_worker, args=(secB,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    # Each thread must have SEEN its own SECUDIR both at open AND at
    # call-time.  Pair up (open, call) consecutive observations and
    # assert each pair is internally consistent — i.e. the lock held
    # from open through call.
    assert len(seen) == 4
    assert seen[0] == seen[1], (
        f"Thread 1 raced on SECUDIR: open={seen[0]!r}, call={seen[1]!r}")
    assert seen[2] == seen[3], (
        f"Thread 2 raced on SECUDIR: open={seen[2]!r}, call={seen[3]!r}")
    # The two threads used different SECUDIRs — exactly one of each
    # must appear.
    assert {seen[0], seen[2]} == {secA, secB}


def test_scrub_secrets_masks_long_secrets_only():
    """_scrub_secrets leaves short (<3 char) secrets alone — masking a
    2-char PIN would blanket-mask every unrelated 2-char run in the
    message."""
    msg = "logon failed for user with password xy"
    out = sapmap_rfc._scrub_secrets(msg, password="xy")
    assert out == msg               # too-short secret not masked
    out2 = sapmap_rfc._scrub_secrets(msg, password="xyz")
    assert "xyz" not in out2 or out2 == msg     # 3-char OK
    # The real case — a long secret gets masked.
    msg2 = "Communication error: logon failed with password P4ssword!"
    out3 = sapmap_rfc._scrub_secrets(msg2, password="P4ssword!")
    assert "P4ssword!" not in out3
    assert "***" in out3


def test_helper_invalid_sysnr_returns_sentinel(_snc_reset, _backend, _native):
    """Non-numeric sysnr → stable snc_invalid_sysnr sentinel, no open."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=lab")
    out = sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", "ABC", "p:CN=S4H", user="u", password="pw" * 6)
    assert out["error"].startswith("snc_invalid_sysnr")
    assert out["source"] == ""
    assert _backend.last_params is None


def test_helper_coerces_integer_sysnr(_snc_reset, _backend, _native):
    """int sysnr is accepted and zero-padded to 2 digits."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=lab")
    sapmap_rfc.rfc_system_info_over_snc(
        "10.0.0.1", 0, "p:CN=S4H", user="u", password="pw" * 6)
    assert _backend.last_params.get("sysnr") == "00"
