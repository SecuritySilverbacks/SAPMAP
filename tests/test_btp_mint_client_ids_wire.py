"""State-serialisation contract for the cert-auth mint client_id cache.

The Phase-4 UI (Mint Token via Cert-Auth modal) pre-fills the
client_id field from a cache the backend maintains — see
sapmap_gui.py::_post_mint_auto_enumerate and the
/mint_btp_token_via_cert route's client_id caching block.

Two things must hold across GUI restarts / snapshot loads:

  1. The client_id map is *never* persisted to disk (via
     SAPMAPState.to_dict).  It's a semi-secret; leaking it into
     .sapmap files would tempt operators to commit sensitive
     material to git.

  2. The map IS exposed on the LIVE /api/state wire response as
     btp_mint_client_ids with string keys shaped
     "<subaccount_uuid>|<destination_name>" — Python tuples don't
     JSON-serialise, so the (uuid, dest) tuple key is joined.
     The frontend's modal reads this same shape.

Regression pins (2026-07-10, RFC-8705 cert-auth mint Phase 4).
"""
from __future__ import annotations

import json

import modules  # noqa: F401  (registers package paths)
from sapmap_models import SAPMAPState


class _FakeApi:
    """Minimal stand-in for the real `api` scope built by
    ``create_app`` — only the fields ``get_state_dict`` reads."""
    def __init__(self):
        self.state = SAPMAPState()
        self.scan_state = "idle"
        self.scan_error = ""
        self.btp_tokens = {}
        self.btp_proxy_override = ""
        self.btp_proxy_auth_token = ""
        self.btp_mint_client_ids = {}


def _get_state_dict(api):
    """Invoke the real ``get_state_dict`` bound-method logic without
    spinning up the full app.  The method lives on the SAPMAPApi
    class inside sapmap_gui.py — we replicate the call by importing
    the method reference and binding it to our fake instance."""
    from modules.core import sapmap_gui as gui
    return gui.SAPMAPApi.get_state_dict(api)


# ---------------------------------------------------------------------------
# Wire shape
# ---------------------------------------------------------------------------

def test_empty_cache_serialises_as_empty_object():
    """Fresh session, no mints yet — the frontend must still see the
    field (not undefined) so ``mapState.btp_mint_client_ids || {}``
    isn't the only guard."""
    api = _FakeApi()
    d = _get_state_dict(api)
    assert "btp_mint_client_ids" in d
    assert d["btp_mint_client_ids"] == {}


def test_populated_cache_serialises_with_joined_string_keys():
    """After a successful cert-auth mint, the cache carries tuple
    keys ``(subaccount_uuid, dest_name)``.  On the wire those become
    ``"<uuid>|<dest_name>"`` — Python tuples aren't JSON-native and
    the frontend joins the same way to read them back."""
    api = _FakeApi()
    api.btp_mint_client_ids = {
        ("90a90189-8c94-44ff-9f76-b50a42c0fd98", "TO_BTP"):
            "sb-clone…!b609810|destination-xsappname!b404",
        ("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "OTHER_DEST"):
            "sb-other!b123|other-xsappname!b7",
    }
    d = _get_state_dict(api)
    wire = d["btp_mint_client_ids"]
    assert isinstance(wire, dict)
    assert "90a90189-8c94-44ff-9f76-b50a42c0fd98|TO_BTP" in wire
    assert wire["90a90189-8c94-44ff-9f76-b50a42c0fd98|TO_BTP"] == (
        "sb-clone…!b609810|destination-xsappname!b404")
    assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee|OTHER_DEST" in wire


def test_wire_shape_is_json_round_trippable():
    """The whole dict must survive json.dumps → json.loads — that's
    what actually happens on the way to the browser.  Regression
    catch for anyone accidentally putting a tuple key back in."""
    api = _FakeApi()
    api.btp_mint_client_ids = {
        ("zid1", "d1"): "cid1",
        ("zid2", "d2"): "cid2",
    }
    d = _get_state_dict(api)
    encoded = json.dumps(d["btp_mint_client_ids"])
    decoded = json.loads(encoded)
    assert decoded == {"zid1|d1": "cid1", "zid2|d2": "cid2"}


# ---------------------------------------------------------------------------
# Disk safety
# ---------------------------------------------------------------------------

def test_client_id_cache_not_in_state_todict():
    """SAPMAPState.to_dict serialises to disk (.sapmap file).  The
    client_id cache MUST NOT appear there — semi-secret material
    doesn't belong in a snapshot the operator might commit to git."""
    state = SAPMAPState()
    d = state.to_dict()
    assert "btp_mint_client_ids" not in d, (
        "regression: cert-auth mint client_id cache is leaking into "
        "the .sapmap snapshot — must stay process-memory only")


def test_client_id_cache_missing_attr_still_serialises():
    """Older sessions (loaded from a snapshot minted before Phase 4)
    won't have the attribute yet.  get_state_dict must not crash —
    it should treat missing as empty."""
    api = _FakeApi()
    del api.btp_mint_client_ids   # simulate the pre-fix attribute layout
    d = _get_state_dict(api)
    assert d["btp_mint_client_ids"] == {}
