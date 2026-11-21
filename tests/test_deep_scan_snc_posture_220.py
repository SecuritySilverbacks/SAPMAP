"""Issue #220 — deep-scan nodes reach the full SNC posture spectrum.

The deep-scan SAPology bridge (``_sapology_system_to_node`` and its
``deep_scan_single`` caller) used to classify SNC posture with a TCP-only
tail, so an SNC-enforced node could never leave ``enforced_no_creds`` until
a shallow re-enrich ran.  Issue #220 threads the operator's active SNC
context (per-node ``snc_partnername`` + best credential + active looted-PSE
wallet) through the bridge, gated on the sibling kloris/SAPology PR that adds
the opt-in ``creds`` bundle, so a deep-scan node can reach ``reachable_auth``.

These tests use mocks/fixtures only — no live SAP box.  They cover:
  * the SAPology capability gate (``_fn_accepts_kw``) + creds-bundle builder,
  * the bridge's gated SNC-auth path (disabled by default; reach-hint + rate
    limit preserved; ``reachable_auth`` promotion + field backfill),
  * ``deep_scan_single`` threading the bundle to SAPology and promoting the
    node, and graceful degradation against an older SAPology, and
  * a live check that the MODIFIED sibling ../SAPology accepts the bundle.
"""

import inspect
import sys
import time
import types

import pytest

import sapmap_rfc
import sapmap_scanner
from sapmap_models import (
    Credentials, InstanceInfo, SAPMAPState, SAPNode, TrustRelation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def _snc_reset():
    """Snapshot + scrub the SNC module globals so a leaked active looted
    cred / operator posture from another test can't skew our verdicts, and
    restore them on teardown.  Mirrors the fixture in
    test_snc_aware_rfcsi_167.py, including the live-module rebind guard."""
    live = sys.modules.get("sapmap_rfc", sapmap_rfc)
    globals()["sapmap_rfc"] = live
    saved_cfg = dict(live._snc_config)
    saved_cred = (dict(live._snc_active_cred)
                  if live._snc_active_cred else None)
    live.set_snc_config(secudir="", sapcryptolib="", identity="")
    live.set_snc_identity(None)
    try:
        yield live
    finally:
        live.set_snc_config(**saved_cfg)
        live.set_snc_identity(saved_cred)


def _activate_looted_wallet(live, *, source_sid="A4H"):
    """Set an active looted-PSE wallet entry via the CommonCryptoLib path
    (so ``_snc_params_for`` returns non-empty without needing the native
    saprfclib backend) — the 'wallet-active looted PSE' of issue #220."""
    live.set_snc_config(secudir="/secudir", sapcryptolib="/opt/sap/lib.so",
                        identity="p:CN=sapmap-lab")
    live.set_snc_identity({
        "cred_id": f"{source_sid}:SAPSYS", "source_sid": source_sid,
        "pse_path": f"/loot/pse/{source_sid}/SAPSYS.pse", "cred_v2_path": "",
        "pin": "", "snc_identity": f"p:CN={source_sid}",
        "key_is_rsa": True, "path_pref": "cryptolib",
    })


# --- Fake SAPology SAPSystem / SAPInstance ---------------------------------

class _FakeInst:
    def __init__(self):
        self.instance_nr = "00"
        self.ip = "10.0.0.1"
        self.ports = {3300: "gateway"}
        self.services = {}
        self.info = {}
        self.findings = []

    def to_dict(self):
        return {"instance_nr": self.instance_nr, "ports": {"3300": "gateway"}}


class _FakeSys:
    def __init__(self, sid="UNKNOWN", snc_partnername=""):
        self.sid = sid
        self.hostname = ""
        self.os_type = ""
        self.db_type = ""
        self.kernel = ""
        self.sap_release = ""
        self.system_type = "ABAP"
        self.clients = []
        self.instances = [_FakeInst()]
        self.has_hana = False
        self.has_maxdb = False
        self.has_mssql = False
        self.has_oracle = False
        self.has_db2 = False
        self.snc_partnername = snc_partnername
        self.snc_creds_supplied = False

    def to_dict(self):
        return {"sid": self.sid}


def _make_fake_sapology(sys_obj, *, accept_creds=True, version="1.1.0"):
    """Build a stand-in SAPology module.  ``accept_creds`` controls whether
    its entry points carry the opt-in ``creds`` kwarg (new) or not (old)."""
    rec = {"disc": [], "assess": []}
    if accept_creds:
        def discover_systems(targets, instances, timeout=3, threads=20,
                             verbose=False, cancel_check=None, client_enum=True,
                             skip_alive=True, inventory=None,
                             inventory_skip=False, creds=None):
            rec["disc"].append({"targets": targets, "creds": creds})
            return [sys_obj]

        def assess_vulnerabilities(landscape, gw_cmd="whoami", timeout=5,
                                   verbose=False, url_scan=False,
                                   url_scan_threads=25, cancel_check=None,
                                   default_creds=False, creds=None):
            rec["assess"].append({"creds": creds})
            return landscape
    else:
        def discover_systems(targets, instances, timeout=3, threads=20,
                             verbose=False, cancel_check=None, client_enum=True,
                             skip_alive=True, inventory=None,
                             inventory_skip=False):
            rec["disc"].append({"targets": targets})
            return [sys_obj]

        def assess_vulnerabilities(landscape, gw_cmd="whoami", timeout=5,
                                   verbose=False, url_scan=False,
                                   url_scan_threads=25, cancel_check=None,
                                   default_creds=False):
            rec["assess"].append({})
            return landscape

    mod = types.ModuleType("SAPology")
    mod.__version__ = version
    mod.discover_systems = discover_systems
    mod.assess_vulnerabilities = assess_vulnerabilities
    mod._rec = rec
    return mod


_SNC_OK = {
    "source": "rfcsi_snc_auth", "sid": "NPL", "hostname": "npl01",
    "os_type": "Linux", "db_type": "ORA", "kernel": "753",
    "sap_release": "753", "ip": "10.0.0.1", "error": "", "phase": "",
}


# ---------------------------------------------------------------------------
# _fn_accepts_kw + creds-bundle builder
# ---------------------------------------------------------------------------

def test_fn_accepts_kw_detects_param():
    def f(a, b, creds=None):
        return None

    def g(a, b):
        return None

    assert sapmap_scanner._fn_accepts_kw(f, "creds") is True
    assert sapmap_scanner._fn_accepts_kw(g, "creds") is False
    assert sapmap_scanner._fn_accepts_kw(None, "creds") is False


def test_build_creds_bundle_none_without_context(_snc_reset):
    assert sapmap_scanner._build_sapology_creds_bundle("", None, None) is None
    # A credential with no password is not usable on its own.
    c = Credentials(username="SAPMAP00", password="", client="001")
    assert sapmap_scanner._build_sapology_creds_bundle("", c, None) is None


def test_build_creds_bundle_from_partner_and_cred(_snc_reset):
    c = Credentials(username="SAPMAP00", password="pw", client="001")
    bundle = sapmap_scanner._build_sapology_creds_bundle(
        "p:CN=NPL", c, SAPMAPState())
    assert bundle is not None
    assert bundle["snc_partnername"] == "p:CN=NPL"
    assert bundle["user"] == "SAPMAP00"
    assert bundle["password"] == "pw"
    assert isinstance(bundle["snc_config"], dict)


def test_build_creds_bundle_snc_config_is_secrets_free(_snc_reset):
    """The snc_config snapshot carries only booleans + the (non-secret)
    identity DN — never the SECUDIR path, cryptolib path, PIN or password."""
    live = _snc_reset
    _activate_looted_wallet(live)
    c = Credentials(username="SAPMAP00", password="pw", client="001")
    bundle = sapmap_scanner._build_sapology_creds_bundle(
        "p:CN=NPL", c, SAPMAPState())
    cfg = bundle["snc_config"]
    assert cfg["secudir_set"] is True
    assert cfg["sapcryptolib_set"] is True
    assert cfg["active_looted_pse"] is True
    # No raw paths / secrets leaked into the bundle's snc_config.
    assert "/secudir" not in str(cfg)
    assert "/opt/sap/lib.so" not in str(cfg)


# ---------------------------------------------------------------------------
# Bridge — gated SNC-auth classification
# ---------------------------------------------------------------------------

def test_bridge_default_is_tcp_only_no_snc_rfc(monkeypatch):
    """Called with no SNC context (the default), the bridge never fires the
    SNC-auth RFC probe — even when a partner + creds would otherwise be
    available elsewhere — and labels a plain-blocked node enforced_no_creds."""
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    monkeypatch.setattr(
        sapmap_rfc, "rfc_system_info_over_snc",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("SNC RFC must not fire without snc_auth_enabled")))
    node = sapmap_scanner._sapology_system_to_node(_FakeSys("UNKNOWN"),
                                                   "10.0.0.1")
    assert node.snc_posture == "enforced_no_creds"


def test_bridge_disabled_even_with_partner_and_creds(monkeypatch, _snc_reset):
    """snc_auth_enabled=False short-circuits to the TCP-only verdict, so an
    old SAPology (bundle rejected) never triggers an SNC-auth probe."""
    _activate_looted_wallet(_snc_reset)
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    monkeypatch.setattr(
        sapmap_rfc, "rfc_system_info_over_snc",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("SNC RFC must not fire when disabled")))
    node = sapmap_scanner._sapology_system_to_node(
        _FakeSys("UNKNOWN"), "10.0.0.1",
        snc_partnername="p:CN=NPL",
        creds=Credentials(username="SAPMAP00", password="pw", client="001"),
        state=SAPMAPState(), snc_auth_enabled=False, sid_hint="NPL")
    assert node.snc_posture == "enforced_no_creds"


def test_bridge_enabled_promotes_reachable_auth(monkeypatch, _snc_reset):
    """The headline #220 case: wallet-active looted PSE that reaches the
    target promotes an SNC-enforced deep-scan node to reachable_auth and
    backfills the SID/host/kernel the SNC probe recovered."""
    live = _snc_reset
    _activate_looted_wallet(live, source_sid="A4H")
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    monkeypatch.setattr(sapmap_rfc, "rfc_system_info_over_snc",
                        lambda *a, **kw: dict(_SNC_OK))

    st = SAPMAPState()
    st.nodes["NPL"] = SAPNode(sid="NPL")
    # A4H's looted identity reaches NPL per the STRUSTSSO2 trust graph.
    st.trust_relations = [TrustRelation(trusting_sid="NPL", issuer_sid="A4H")]

    node = sapmap_scanner._sapology_system_to_node(
        _FakeSys("UNKNOWN"), "10.0.0.1",
        snc_partnername="p:CN=NPL",
        creds=Credentials(username="SAPMAP00", password="pw", client="001"),
        state=st, snc_auth_enabled=True, sid_hint="NPL")

    assert node.snc_posture == "reachable_auth"
    # UNK_ SID upgraded + blanks backfilled from the SNC probe.
    assert node.sid == "NPL"
    assert node.hostname == "npl01"
    assert node.kernel == "753"


def test_bridge_enabled_reach_hint_blocks(monkeypatch, _snc_reset):
    """Reach-hint gate still applies on the deep-scan path: a looted cred
    whose source_sid can't reach the target never opens an SNC connection
    and routes to enforced_no_creds."""
    live = _snc_reset
    _activate_looted_wallet(live, source_sid="A4H")
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    called = {"n": 0}

    def _spy(*a, **kw):
        called["n"] += 1
        return dict(_SNC_OK)

    monkeypatch.setattr(sapmap_rfc, "rfc_system_info_over_snc", _spy)

    st = SAPMAPState()
    st.nodes["NPL"] = SAPNode(sid="NPL")
    # A4H reaches OTH only — NOT NPL.
    st.trust_relations = [TrustRelation(trusting_sid="OTH", issuer_sid="A4H")]

    node = sapmap_scanner._sapology_system_to_node(
        _FakeSys("UNKNOWN"), "10.0.0.1",
        snc_partnername="p:CN=NPL",
        creds=Credentials(username="SAPMAP00", password="pw", client="001"),
        state=st, snc_auth_enabled=True, sid_hint="NPL")

    assert node.snc_posture == "enforced_no_creds"
    assert called["n"] == 0
    assert node.snc_info.get("last_probe_phase") == "reach_hint_blocked"


def test_bridge_enabled_rate_limit_sticky(monkeypatch, _snc_reset):
    """300 s rate limit still applies: a node probed <300 s ago is skipped
    (the helper is never called) and the bridge records the rate_limited
    phase for triage."""
    live = _snc_reset
    _activate_looted_wallet(live, source_sid="A4H")
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    called = {"n": 0}

    def _spy(*a, **kw):
        called["n"] += 1
        return dict(_SNC_OK)

    monkeypatch.setattr(sapmap_rfc, "rfc_system_info_over_snc", _spy)

    st = SAPMAPState()
    probed = SAPNode(sid="NPL")
    probed.snc_info = {"last_probe_at": time.time() - 60}   # 60 s ago
    st.nodes["NPL"] = probed

    node = sapmap_scanner._sapology_system_to_node(
        _FakeSys("UNKNOWN"), "10.0.0.1",
        snc_partnername="p:CN=NPL",
        creds=Credentials(username="SAPMAP00", password="pw", client="001"),
        state=st, snc_auth_enabled=True, sid_hint="NPL")

    assert called["n"] == 0                       # rate-limited, no probe
    assert node.snc_info.get("last_probe_phase") == "rate_limited"


# ---------------------------------------------------------------------------
# deep_scan_single — end-to-end through a stand-in SAPology
# ---------------------------------------------------------------------------

def _mk_deep_scan_node():
    inst = InstanceInfo(instance_nr="00", ip="10.0.0.1",
                        ports={3300: "gateway"})
    return SAPNode(
        sid="NPL", hostname="10.0.0.1", ip="10.0.0.1", instances=[inst],
        snc_partnername="p:CN=NPL",
        credentials=[Credentials(username="SAPMAP00", password="pw",
                                 client="001")])


def test_deep_scan_single_threads_creds_and_promotes(monkeypatch, _snc_reset):
    """deep-scan import: with a new SAPology that accepts the bundle and a
    wallet-active looted PSE reaching the target, the node is promoted to
    reachable_auth AND SAPology received the creds bundle carrying the SNC
    partner name."""
    live = _snc_reset
    _activate_looted_wallet(live, source_sid="A4H")
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    monkeypatch.setattr(sapmap_rfc, "rfc_system_info_over_snc",
                        lambda *a, **kw: dict(_SNC_OK))

    fake = _make_fake_sapology(_FakeSys("UNKNOWN"), accept_creds=True)
    monkeypatch.setitem(sys.modules, "SAPology", fake)

    st = SAPMAPState()
    node = _mk_deep_scan_node()
    st.add_node(node)
    st.trust_relations = [TrustRelation(trusting_sid="NPL", issuer_sid="A4H")]

    out = sapmap_scanner.deep_scan_single(node, state=st)

    assert out.snc_posture == "reachable_auth"
    # SAPology was handed the opt-in bundle, carrying the SNC partner.
    assert fake._rec["disc"], "discover_systems was not called"
    passed = fake._rec["disc"][0]["creds"]
    assert passed is not None
    assert passed["snc_partnername"] == "p:CN=NPL"
    assert fake._rec["assess"][0]["creds"] is not None


def test_deep_scan_single_old_sapology_degrades_gracefully(
        monkeypatch, _snc_reset):
    """Against an older SAPology WITHOUT the creds kwarg, deep_scan_single
    must not raise (never passes creds) and leaves the node at the TCP-only
    verdict — proving the SNC-auth upgrade is gated on the sibling PR."""
    live = _snc_reset
    _activate_looted_wallet(live, source_sid="A4H")
    monkeypatch.setattr(sapmap_scanner, "_tcp_reach", lambda h, p, **kw: True)
    monkeypatch.setattr(
        sapmap_rfc, "rfc_system_info_over_snc",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("SNC RFC must not fire against an old SAPology")))

    fake = _make_fake_sapology(_FakeSys("UNKNOWN"), accept_creds=False)
    monkeypatch.setitem(sys.modules, "SAPology", fake)

    st = SAPMAPState()
    node = _mk_deep_scan_node()
    st.add_node(node)

    out = sapmap_scanner.deep_scan_single(node, state=st)

    assert out.snc_posture == "enforced_no_creds"
    # Old signature → no creds kwarg recorded.
    assert "creds" not in fake._rec["disc"][0]


# ---------------------------------------------------------------------------
# Live check — the MODIFIED sibling ../SAPology accepts the bundle
# ---------------------------------------------------------------------------

def test_real_sibling_sapology_accepts_creds_bundle():
    """Resolve the sibling SAPology the same way the deep-scan path does and
    confirm the MODIFIED checkout accepts the opt-in creds bundle + declares
    a version.  Skips cleanly when SAPology isn't checked out as a sibling
    (e.g. SAPMAP-only CI)."""
    sapmap_scanner.set_sapology_path(sapmap_scanner._default_sapology_dir())
    sys.modules.pop("SAPology", None)
    try:
        import SAPology
    except Exception as exc:                       # pragma: no cover
        pytest.skip(f"sibling SAPology not importable: {exc}")
    if not hasattr(SAPology, "discover_systems"):  # pragma: no cover
        pytest.skip("SAPology import is an empty namespace package")
    try:
        disc = inspect.signature(SAPology.discover_systems).parameters
        assess = inspect.signature(SAPology.assess_vulnerabilities).parameters
        assert "creds" in disc, (
            "sibling SAPology is missing the issue #220 creds kwarg on "
            "discover_systems — update ../SAPology to the companion PR")
        assert "creds" in assess
        assert isinstance(getattr(SAPology, "__version__", None), str)
    finally:
        sys.modules.pop("SAPology", None)
