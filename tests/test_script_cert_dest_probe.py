"""ScriptRunner: cert-auth destination probe action.

Pin down the YAML→endpoint mapping so scripted scenarios can use
the kernel-proxied HTTP primitive without clicking through the GUI:

  - action: cert_dest_probe
    target: AE1
    destination: TEST_MARCH

Not in DESTRUCTIVE_ACTIONS — the probe is read-only from the
target's perspective (a GET against the destination service).
Dry-runs fire it normally.
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_script import (
    _map_step, _ACTION_LABELS, DESTRUCTIVE_ACTIONS)


def _step(action, **kw):
    s = {"action": action}
    s.update(kw)
    return s


def test_cert_dest_probe_maps_to_endpoint():
    method, path, body, wait = _map_step(_step(
        "cert_dest_probe", target="AE1", destination="TEST_MARCH"))
    assert method == "POST"
    assert path == "/api/node/AE1/cert_dest_probe"
    assert body == {"destination_name": "TEST_MARCH"}
    assert wait is True


def test_cert_dest_probe_is_read_only_not_destructive():
    """The primitive issues a GET / — no state change on the target
    from the operator's perspective.  Dry-run playbooks should fire
    it normally so they see BTP loot even without --confirm."""
    assert "cert_dest_probe" not in DESTRUCTIVE_ACTIONS


def test_cert_dest_probe_has_human_label():
    assert "cert_dest_probe" in _ACTION_LABELS
    assert "destination" in _ACTION_LABELS["cert_dest_probe"].lower()
