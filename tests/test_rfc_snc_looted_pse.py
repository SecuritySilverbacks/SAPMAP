"""Issue #137 — looted-PSE SNC *client* identity (connection layer).

SAPMAP's default SNC client identity is the single global operator
posture (``set_snc_config``).  #137 lets a PSE looted off a pwned box
stand in as the client identity so SAPMAP can speak RFC-over-SNC to every
system that trusts it.  saprfclib 0.2.0 adds a *native* pure-Python SNC
path (``snc_pse`` — no CommonCryptoLib binary) that works for RSA PSEs;
EC/system PSEs route to the CommonCryptoLib (``snc_lib``) path.

These tests pin the path-selection logic, the operator→looted override,
backend gating (native never emitted to a backend that can't honor it),
the manual override, secret handling, lossless serialization, and the
end-to-end threading into ``rfc_check_credentials`` / ``_get_connection``
— all without a real SDK or a real PSE.
"""
import json
import os

import pytest

import sapmap_rfc
from sapmap_models import SNCCredential, SAPMAPState, SAPNode, Credentials


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def _snc_reset():
    """Save/restore BOTH SNC module globals (the operator posture AND the
    active looted identity) so these tests never leak into others."""
    saved_cfg = dict(sapmap_rfc._snc_config)
    saved_cred = (dict(sapmap_rfc._snc_active_cred)
                  if sapmap_rfc._snc_active_cred else None)
    try:
        yield
    finally:
        sapmap_rfc.set_snc_config(**saved_cfg)
        sapmap_rfc.set_snc_identity(saved_cred)


@pytest.fixture
def _native(monkeypatch):
    """Force the native SNC backend to be reported AVAILABLE (so `auto`
    picks native for an RSA key), independent of which backend is
    installed on the test host."""
    monkeypatch.setattr(sapmap_rfc, "_snc_native_available", lambda: True)


def _cred(**over):
    base = dict(cred_id="S4H:SAPSYS", source_sid="S4H",
                pse_path="/loot/pse/S4H/SAPSYS.pse", cred_v2_path="",
                pin="", snc_identity="p:CN=S4H", key_is_rsa=True,
                path_pref="auto")
    base.update(over)
    return base


class _CaptureConn:
    """Fake RFC backend capturing the connection params."""
    last_params = None

    def __init__(self, sdk_path=None, **params):
        type(self).last_params = dict(params)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ping_verbose(self):
        return True, "", ""


def _install_fake_pse(monkeypatch, loader):
    """Install a fake ``saprfclib.pse`` module exposing ``load_pse``."""
    import sys
    import types
    fake = types.ModuleType("saprfclib.pse")
    fake.load_pse = loader
    monkeypatch.setitem(sys.modules, "saprfclib.pse", fake)


# ===========================================================================
# Model — SNCCredential + wallet
# ===========================================================================

def test_snc_credential_defaults_and_roundtrip():
    c = SNCCredential(source_sid="S4H", pse_path="/p/SAPSYS.pse",
                      snc_identity="p:CN=S4H", key_is_rsa=False)
    assert c.cred_id == "S4H:SAPSYS"        # derived from sid + PSE stem
    assert c.path_pref == "auto"
    d = c.to_dict()
    assert SNCCredential.from_dict(d).to_dict() == d
    # unknown keys ignored; bogus path_pref normalised to auto
    c2 = SNCCredential.from_dict({**d, "bogus": 1, "path_pref": "weird"})
    assert c2.path_pref == "auto"


def test_to_dict_is_exactly_ten_keys():
    """Pin to_dict against an explicit literal so a dropped/added field is
    caught (a symmetric from_dict(d).to_dict()==d check cannot see a field
    missing from BOTH sides)."""
    c = SNCCredential(cred_id="S4H:SAPSYS", source_sid="S4H",
                      pse_path="/loot/SAPSYS.pse", cred_v2_path="/loot/cv2",
                      pin="secret", snc_identity="p:CN=S4H", key_is_rsa=True,
                      path_pref="native", source_label="box1",
                      looted_at="2026-11-11")
    assert c.to_dict() == {
        "cred_id": "S4H:SAPSYS", "source_sid": "S4H",
        "pse_path": "/loot/SAPSYS.pse", "cred_v2_path": "/loot/cv2",
        "pin": "secret", "snc_identity": "p:CN=S4H", "key_is_rsa": True,
        "path_pref": "native", "source_label": "box1",
        "looted_at": "2026-11-11",
    }


def test_full_state_roundtrip_preserves_every_field():
    """Through a REAL json.dumps/loads cycle (what .sapmap does), read
    every secret-bearing field back off the deserialized object — not just
    the symmetric self-compare."""
    st = SAPMAPState()
    st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/loot/SAPSYS.pse",
        cred_v2_path="/loot/cv2", pin="PINPIN", snc_identity="p:CN=S4H",
        key_is_rsa=True, path_pref="native", source_label="box1"))
    st.set_active_snc_credential("S4H:SAPSYS")
    back = SAPMAPState.from_dict(
        json.loads(json.dumps(st.to_dict()))).active_snc_credential()
    assert back.pse_path == "/loot/SAPSYS.pse"
    assert back.cred_v2_path == "/loot/cv2"
    assert back.pin == "PINPIN"
    assert back.snc_identity == "p:CN=S4H"
    assert back.key_is_rsa is True
    assert back.path_pref == "native"
    assert back.source_label == "box1"
    assert back.cred_id == "S4H:SAPSYS"


def test_key_is_rsa_none_survives_roundtrip():
    """None (unprobed) and False (EC) route DIFFERENTLY in auto, so None
    must NOT be coerced to False (or True) across a JSON round-trip."""
    c = SNCCredential(source_sid="S4H", pse_path="/p/SAPSYS.pse",
                      key_is_rsa=None)
    back = SNCCredential.from_dict(json.loads(json.dumps(c.to_dict())))
    assert back.key_is_rsa is None


def test_pin_not_in_repr():
    """The PIN must not leak through the default dataclass repr (future
    print(cred)/log/traceback-locals), but must still serialize."""
    c = SNCCredential(source_sid="S4H", pse_path="/p/SAPSYS.pse",
                      pin="TopSecretPIN")
    r = repr(c)
    assert "TopSecretPIN" not in r
    assert "pin=" not in r
    assert c.to_dict()["pin"] == "TopSecretPIN"


def test_wallet_add_select_and_state_roundtrip():
    st = SAPMAPState()
    st.add_snc_credential(SNCCredential(**_cred(key_is_rsa=False)))
    assert st.active_snc_credential() is None          # nothing active yet
    assert st.set_active_snc_credential("S4H:SAPSYS") is True
    assert st.set_active_snc_credential("ghost") is False   # unknown rejected
    assert st.active_snc_credential().snc_identity == "p:CN=S4H"
    st2 = SAPMAPState.from_dict(st.to_dict())
    assert st2.active_snc_cred_id == "S4H:SAPSYS"
    assert st2.active_snc_credential().key_is_rsa is False
    assert st2.set_active_snc_credential("") is True
    assert st2.active_snc_credential() is None


def test_active_credential_stale_id_is_safe():
    st = SAPMAPState()
    st.active_snc_cred_id = "gone"
    assert st.active_snc_credential() is None


def test_different_pse_same_sid_get_distinct_ids():
    """Two PSEs looted from one box with different filenames derive
    distinct ids (the stem, not a hardcoded :SAPSYS)."""
    a = SNCCredential(source_sid="S4H", pse_path="/loot/SAPSYS.pse")
    b = SNCCredential(source_sid="S4H", pse_path="/loot/OTHER.pse")
    assert a.cred_id == "S4H:SAPSYS"
    assert b.cred_id == "S4H:OTHER"


def test_add_snc_credential_disambiguates_colliding_ids():
    """A DIFFERENT PSE colliding on the same id gets a #N suffix instead of
    silently clobbering the first; re-adding the SAME path updates in place.
    The wallet-key == stored-cred-id invariant is preserved throughout."""
    st = SAPMAPState()
    a = st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/dirA/SAPSYS.pse", snc_identity="p:CN=A"))
    b = st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/dirB/SAPSYS.pse", snc_identity="p:CN=B"))
    assert a.cred_id == "S4H:SAPSYS"
    assert b.cred_id == "S4H:SAPSYS#2"
    assert len(st.snc_credentials) == 2
    for k, v in st.snc_credentials.items():
        assert k == v.cred_id
    # re-add same pse_path -> overwrite in place (update semantics)
    a2 = st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/dirA/SAPSYS.pse", snc_identity="p:CN=A2"))
    assert a2.cred_id == "S4H:SAPSYS"
    assert len(st.snc_credentials) == 2
    assert st.snc_credentials["S4H:SAPSYS"].snc_identity == "p:CN=A2"


# ===========================================================================
# Path selection — _snc_params_for with a looted identity
# ===========================================================================

def test_operator_posture_unchanged_when_no_looted_identity(_snc_reset):
    """Regression guard: with no looted identity active, the gate is the
    original operator-posture behaviour, byte-for-byte."""
    sapmap_rfc.set_snc_identity(None)
    sapmap_rfc.set_snc_config(secudir="/sec", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    assert sapmap_rfc._snc_params_for("p:CN=T") == {
        "snc_sso": "0", "snc_myname": "p:CN=Me",
        "snc_partnername": "p:CN=T", "snc_lib": "/lib.so",
    }
    assert sapmap_rfc._snc_params_for("") == {}


def test_operator_posture_partial_config_is_off(_snc_reset):
    """Pins the AND-conjunction of the operator gate: any missing leg (with
    no looted identity) yields {}.  Catches an and→or mutation."""
    sapmap_rfc.set_snc_identity(None)
    sapmap_rfc.set_snc_config(secudir="/sec", sapcryptolib="", identity="")
    assert sapmap_rfc._snc_params_for("p:CN=T") == {}
    sapmap_rfc.set_snc_config(secudir="/sec", sapcryptolib="/l.so",
                              identity="")
    assert sapmap_rfc._snc_params_for("p:CN=T") == {}
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="/l.so",
                              identity="p:CN=Me")
    assert sapmap_rfc._snc_params_for("p:CN=T") == {}


def test_looted_rsa_auto_uses_native_path(_snc_reset, _native):
    sapmap_rfc.set_snc_config(secudir="/sec", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert p == {
        "snc_sso": "0", "snc_partnername": "p:CN=T",
        "snc_myname": "p:CN=S4H",            # looted identity, NOT operator
        "snc_pse": "/loot/pse/S4H/SAPSYS.pse", "snc_pse_pin": "",
    }
    assert "snc_lib" not in p


def test_looted_rsa_native_includes_cred_v2_when_present(_snc_reset, _native):
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, pin="1234",
                                      cred_v2_path="/loot/pse/S4H/cred_v2"))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert p["snc_pse_pin"] == "1234"
    assert p["snc_credential"] == "/loot/pse/S4H/cred_v2"


def test_looted_native_omits_myname_when_identity_empty(_snc_reset, _native):
    """snc_myname is emitted only when the cred carries an identity — an
    empty one must NOT inject snc_myname=''."""
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, snc_identity=""))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert "snc_myname" not in p
    assert p.get("snc_pse") == "/loot/pse/S4H/SAPSYS.pse"


def test_looted_ec_auto_falls_back_to_commoncryptolib(_snc_reset, _native):
    """An EC PSE can't use the native path (saprfclib#64) → CommonCryptoLib,
    reusing the operator-configured crypto lib with the looted identity."""
    sapmap_rfc.set_snc_config(secudir="/sec", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=False))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert p == {
        "snc_sso": "0", "snc_partnername": "p:CN=T",
        "snc_myname": "p:CN=S4H", "snc_lib": "/lib.so",
    }
    assert "snc_pse" not in p


def test_looted_ec_without_cryptolib_cannot_negotiate(_snc_reset, _native):
    """EC PSE but no crypto lib configured → SNC simply can't be done → {}."""
    sapmap_rfc.set_snc_config(secudir="", sapcryptolib="", identity="")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=False))
    assert sapmap_rfc._snc_params_for("p:CN=T") == {}


def test_unprobed_key_auto_uses_cryptolib(_snc_reset, _native):
    """key_is_rsa=None (not yet probed) → auto routes to the SAFE default
    (CommonCryptoLib); native is reserved for an affirmatively-RSA key.
    This pins the `key_is_rsa is True` trigger (an `is not False` mutation
    would send None→native and fail here)."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=None))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert "snc_lib" in p and "snc_pse" not in p


def test_path_pref_cryptolib_overrides_rsa(_snc_reset, _native):
    """Manual override: force CommonCryptoLib even for an RSA key."""
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, path_pref="cryptolib"))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert "snc_lib" in p and "snc_pse" not in p


def test_path_pref_native_overrides_ec_when_backend_supports_it(_snc_reset,
                                                                _native):
    """Manual override: force native even for an EC key — allowed while the
    backend can attempt native (the connect may still fail, operator's
    call)."""
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=False, path_pref="native",
                                      pin="x"))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert p.get("snc_pse") == "/loot/pse/S4H/SAPSYS.pse"
    assert "snc_lib" not in p


def test_path_pref_native_downgrades_on_non_native_backend(_snc_reset,
                                                           monkeypatch):
    """Security-critical: a forced-native cred on the C-SDK backend (no
    snc_pse support) must NOT emit native-only params (which the SDK drops,
    sending the logon in the clear) — it downgrades to CommonCryptoLib."""
    monkeypatch.setattr(sapmap_rfc, "_snc_native_available", lambda: False)
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, path_pref="native"))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert "snc_pse" not in p
    assert p.get("snc_lib") == "/lib.so"


def test_auto_falls_back_to_cryptolib_when_native_unavailable(_snc_reset,
                                                              monkeypatch):
    """C SDK backend (native unavailable) → even an RSA looted PSE routes to
    CommonCryptoLib, since the native snc_pse path is saprfclib-only."""
    monkeypatch.setattr(sapmap_rfc, "_snc_native_available", lambda: False)
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, path_pref="auto"))
    p = sapmap_rfc._snc_params_for("p:CN=T")
    assert "snc_lib" in p and "snc_pse" not in p


def test_empty_pse_path_yields_no_params(_snc_reset, _native):
    sapmap_rfc.set_snc_identity(_cred(pse_path=""))
    assert sapmap_rfc._snc_params_for("p:CN=T") == {}


def test_empty_partner_name_yields_no_params(_snc_reset, _native):
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True))
    assert sapmap_rfc._snc_params_for("") == {}
    assert sapmap_rfc._snc_params_for("   ") == {}


def test_set_snc_identity_none_reverts_to_operator(_snc_reset, _native):
    sapmap_rfc.set_snc_config(secudir="/s", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True))
    assert "snc_pse" in sapmap_rfc._snc_params_for("p:CN=T")
    sapmap_rfc.set_snc_identity(None)       # clear
    assert sapmap_rfc._snc_params_for("p:CN=T")["snc_lib"] == "/lib.so"


def test_set_snc_config_preserves_active_looted_identity(_snc_reset, _native):
    """Re-saving the operator posture must NOT wipe the active looted
    identity (independent module globals)."""
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True))
    sapmap_rfc.set_snc_config(secudir="/new", sapcryptolib="/new.so",
                              identity="p:CN=Other")
    assert "snc_pse" in sapmap_rfc._snc_params_for("p:CN=T")


# ===========================================================================
# _snc_native_available — exercise the real body (module-name match)
# ===========================================================================

def test_native_available_matches_backend_module(monkeypatch):
    class _Pure:
        pass
    _Pure.__module__ = "sap_rfc_pure"

    class _CSDK:
        pass
    _CSDK.__module__ = "sap_rfc_ctypes"

    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _Pure)
    assert sapmap_rfc._snc_native_available() is True
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _CSDK)
    assert sapmap_rfc._snc_native_available() is False

    def _boom():
        raise RuntimeError("no backend")
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", _boom)
    assert sapmap_rfc._snc_native_available() is False


# ===========================================================================
# _pse_key_is_rsa probe
# ===========================================================================

def test_probe_rsa_true(monkeypatch, tmp_path):
    pse = tmp_path / "rsa.pse"
    pse.write_bytes(b"\x30\x00stub")
    _install_fake_pse(monkeypatch, lambda data, pin: object())  # loads clean
    assert sapmap_rfc._pse_key_is_rsa(str(pse), "") is True


def test_probe_ec_false(monkeypatch, tmp_path):
    pse = tmp_path / "ec.pse"
    pse.write_bytes(b"\x30\x00stub")

    def _loader(data, pin):
        raise ValueError("PSE key is not an RSA key; only RSA keys are supported")
    _install_fake_pse(monkeypatch, _loader)
    assert sapmap_rfc._pse_key_is_rsa(str(pse), "") is False


def test_probe_inconclusive_on_other_error(monkeypatch, tmp_path):
    """A wrong-PIN / corrupt error must NOT be read as a definitive EC
    verdict (False) — it is inconclusive (None)."""
    pse = tmp_path / "bad.pse"
    pse.write_bytes(b"\x30\x00stub")

    def _loader(data, pin):
        raise ValueError("wrong PSE PIN")
    _install_fake_pse(monkeypatch, _loader)
    assert sapmap_rfc._pse_key_is_rsa(str(pse), "") is None


def test_probe_passes_pin_through(monkeypatch, tmp_path):
    """The stored PIN reaches load_pse; an empty string maps to None (the
    unprotected-PSE convention)."""
    pse = tmp_path / "x.pse"
    pse.write_bytes(b"\x30\x00stub")
    seen = {}

    def _loader(data, pin):
        seen["pin"] = pin
        return object()
    _install_fake_pse(monkeypatch, _loader)
    sapmap_rfc._pse_key_is_rsa(str(pse), "1234")
    assert seen["pin"] == "1234"
    sapmap_rfc._pse_key_is_rsa(str(pse), "")
    assert seen["pin"] is None


def test_probe_missing_file_is_none(monkeypatch):
    _install_fake_pse(monkeypatch, lambda data, pin: object())
    assert sapmap_rfc._pse_key_is_rsa("/no/such/file.pse", "") is None


# ===========================================================================
# End-to-end: rfc_check_credentials + _get_connection thread the identity
# ===========================================================================

def test_rfc_check_credentials_uses_looted_native_identity(_snc_reset, _native,
                                                           monkeypatch):
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _CaptureConn)
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, pin="pw"))
    _CaptureConn.last_params = None
    code, _ = sapmap_rfc.rfc_check_credentials(
        "10.0.0.1", "00", "001", "SAPJSF", "secret",
        snc_partnername="p:CN=T")
    p = _CaptureConn.last_params
    assert code == "SUCCESS"
    assert p["snc_pse"] == "/loot/pse/S4H/SAPSYS.pse"
    assert p["snc_pse_pin"] == "pw"
    assert p["snc_myname"] == "p:CN=S4H"
    assert "snc_lib" not in p


def test_rfc_check_credentials_plain_without_identity_or_name(_snc_reset,
                                                              monkeypatch):
    """No looted identity + no operator posture + no name → no snc_* leak."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _CaptureConn)
    sapmap_rfc.set_snc_identity(None)
    sapmap_rfc.set_snc_config()
    _CaptureConn.last_params = None
    sapmap_rfc.rfc_check_credentials("10.0.0.1", "00", "001", "U", "p")
    assert not any(k.startswith("snc_") for k in _CaptureConn.last_params)


def test_rfc_check_sets_secudir_on_cryptolib_path(_snc_reset, _native,
                                                  monkeypatch):
    """The EC/CommonCryptoLib path mirrors the configured SECUDIR into the
    environment (CommonCryptoLib reads the client PSE from it, not params)."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _CaptureConn)
    monkeypatch.setenv("SECUDIR", "/old")
    sapmap_rfc.set_snc_config(secudir="/opsec", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=False))     # EC -> cryptolib
    sapmap_rfc.rfc_check_credentials("10.0.0.1", "00", "001", "U", "p",
                                     snc_partnername="p:CN=T")
    assert os.environ["SECUDIR"] == "/opsec"


def test_rfc_check_native_path_leaves_secudir_untouched(_snc_reset, _native,
                                                        monkeypatch):
    """The native path needs no SECUDIR and must not overwrite a prior one
    (the 'mirror even on native' regression the #167 comment warns of)."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _CaptureConn)
    monkeypatch.setenv("SECUDIR", "/sentinel")
    sapmap_rfc.set_snc_config(secudir="/opsec", sapcryptolib="/lib.so",
                              identity="p:CN=Me")
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True))      # RSA -> native
    sapmap_rfc.rfc_check_credentials("10.0.0.1", "00", "001", "U", "p",
                                     snc_partnername="p:CN=T")
    assert os.environ["SECUDIR"] == "/sentinel"


def test_get_connection_native_looted_builds_params_without_keyerror(
        _snc_reset, _native, monkeypatch, capsys):
    """_get_connection must build native params AND run its diagnostic print
    without a KeyError (the native path omits snc_lib/snc_myname, which the
    old bracket-indexed print would have crashed on)."""
    monkeypatch.setattr(sapmap_rfc, "_get_rfc_backend", lambda: _CaptureConn)
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True, pin="pw"))
    node = SAPNode(sid="T", ip="10.0.0.1", snc_partnername="p:CN=T")
    creds = Credentials(username="U", password="p", client="001",
                        instance_nr="00")
    _CaptureConn.last_params = None
    conn = sapmap_rfc._get_connection(node, creds)      # must not raise
    assert conn is not None
    p = _CaptureConn.last_params
    assert p["snc_pse"] == "/loot/pse/S4H/SAPSYS.pse"
    assert "snc_lib" not in p
    out = capsys.readouterr().out
    assert "path=native" in out


# ===========================================================================
# State-load wiring: _mirror_snc_config probes + mirrors the active identity
# ===========================================================================

def test_mirror_snc_config_probes_and_tags_active_identity(_snc_reset,
                                                           monkeypatch):
    """On state load, an unprobed active cred gets its key type tagged (so
    `auto` can route it) and the identity reaches the connection layer."""
    from sapmap_gui import _mirror_snc_config
    monkeypatch.setattr(sapmap_rfc, "_pse_key_is_rsa", lambda path, pin: True)
    st = SAPMAPState()
    st.add_snc_credential(SNCCredential(
        source_sid="S4H", pse_path="/loot/SAPSYS.pse",
        snc_identity="p:CN=S4H"))                       # key_is_rsa defaults None
    st.set_active_snc_credential("S4H:SAPSYS")
    assert st.active_snc_credential().key_is_rsa is None
    _mirror_snc_config(st)
    # verdict persisted onto the stored cred (survives the next save)
    assert st.active_snc_credential().key_is_rsa is True
    # and mirrored into the module global with the probed verdict
    assert sapmap_rfc._snc_active_cred is not None
    assert sapmap_rfc._snc_active_cred["pse_path"] == "/loot/SAPSYS.pse"
    assert sapmap_rfc._snc_active_cred["key_is_rsa"] is True


def test_mirror_snc_config_clears_stale_identity_when_none_active(_snc_reset,
                                                                  monkeypatch):
    """Loading a state with no active identity clears any previously-active
    looted identity (no leak across state loads)."""
    from sapmap_gui import _mirror_snc_config
    sapmap_rfc.set_snc_identity(_cred(key_is_rsa=True))     # stale active
    _mirror_snc_config(SAPMAPState())                       # no active identity
    assert sapmap_rfc._snc_active_cred is None
