"""Issue #167 — SNC-aware RFC_SYSTEM_INFO probe.

Phase A tests: SAPNode.snc_posture field basics.  The rest of the suite
(helper contract, classifier branches, GUI route wiring, report
rendering, autopwn skip) is added in later phases.
"""

import json

import pytest

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
