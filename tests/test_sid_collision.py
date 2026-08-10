"""SID-collision handling on SAPMAPState.add_node (issue #25).

Two systems sharing the same 3-char SID used to silently overwrite —
the second add_node() call replaced the first entry in state.nodes,
losing the earlier system entirely.  The new merge/split logic
distinguishes "same physical system rediscovered" (merge) from
"different systems that happen to share a SID" (split under a
disambiguated key).

Disambiguator ladder: installation_number → hostname → IP octet.
"""
from __future__ import annotations

from sapmap_models import SAPMAPState, SAPNode, RFCConnection


def _node(sid, host="", ip="", instno=""):
    return SAPNode(sid=sid, hostname=host, ip=ip,
                    installation_number=instno,
                    system_type="ABAP")


# ---------------------------------------------------------------------------
# Merge case: same physical system rediscovered
# ---------------------------------------------------------------------------

def test_merge_when_same_installation_number():
    """Two adds for the same instno = same license = same system."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="dev-a", ip="10.0.0.1", instno="0021320685"))
    s.add_node(_node("DEV", host="dev-a", ip="10.0.0.1", instno="0021320685"))
    assert list(s.nodes) == ["DEV"]


def test_merge_when_same_hostname_but_no_instno():
    """No instno known yet, hosts match → same physical system."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="devhost", ip="10.0.0.1"))
    s.add_node(_node("DEV", host="DEVHOST", ip=""))   # case-insens
    assert list(s.nodes) == ["DEV"]
    assert s.nodes["DEV"].ip == "10.0.0.1"


def test_merge_when_same_ip_but_hostname_differs():
    """Same IP → same box, even if one banner returned FQDN and the
    other short hostname."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="dev.example.com", ip="10.0.0.5"))
    s.add_node(_node("DEV", host="dev", ip="10.0.0.5"))
    assert list(s.nodes) == ["DEV"]


# ---------------------------------------------------------------------------
# Split case: two different systems that happen to share the SID
# ---------------------------------------------------------------------------

def test_split_when_different_installation_numbers():
    """Two DEV systems, different SAP licenses → split.  Suffix
    picked from last 4 digits of the incoming node's instno."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="dev-a", ip="10.0.0.1",
                      instno="0021320685"))
    s.add_node(_node("DEV", host="dev-b", ip="10.0.0.2",
                      instno="0099887766"))
    keys = sorted(s.nodes)
    assert keys == ["DEV", "DEV#7766"]
    # Original stays under DEV; new one gets the suffixed key
    assert s.nodes["DEV"].hostname == "dev-a"
    assert s.nodes["DEV#7766"].hostname == "dev-b"


def test_split_when_hostnames_differ_no_instno():
    """No instno on either → suffix from the incoming hostname."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="dev-primary", ip="10.0.0.1"))
    s.add_node(_node("DEV", host="dev-cloneland", ip="192.168.1.5"))
    keys = sorted(s.nodes)
    assert keys == ["DEV", "DEV#dev-cloneland"]


def test_split_when_only_ip_available():
    """No hostname on either, only IPs — fall back to last IP octet."""
    s = SAPMAPState()
    s.add_node(_node("DEV", ip="10.0.0.1"))
    s.add_node(_node("DEV", ip="10.0.0.42"))
    assert sorted(s.nodes) == ["DEV", "DEV#42"]


def test_split_uses_instno_over_hostname_when_available():
    """Priority: instno > hostname > IP — even if hostnames differ,
    the last-4-digits-of-instno suffix wins for readability."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="a", ip="1.1.1.1", instno="0011112222"))
    s.add_node(_node("DEV", host="b", ip="2.2.2.2", instno="0033334444"))
    keys = sorted(s.nodes)
    assert keys == ["DEV", "DEV#4444"]


def test_split_survives_three_way_collision():
    """Three unrelated systems on the same SID — second AND third
    get unique disambiguated keys."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="alpha", ip="1.1.1.1"))
    s.add_node(_node("DEV", host="beta",  ip="2.2.2.2"))
    s.add_node(_node("DEV", host="gamma", ip="3.3.3.3"))
    assert sorted(s.nodes) == ["DEV", "DEV#beta", "DEV#gamma"]


# ---------------------------------------------------------------------------
# Round-trip through to_dict / from_dict preserves installation_number
# ---------------------------------------------------------------------------

def test_installation_number_roundtrip():
    s = SAPMAPState()
    s.add_node(_node("DEV", host="dev", ip="10.0.0.1", instno="0021320685"))
    reloaded = SAPMAPState.from_dict(s.to_dict())
    assert reloaded.nodes["DEV"].installation_number == "0021320685"


def test_split_layout_survives_state_reload():
    """A split state must round-trip cleanly — the suffixed key is a
    real SID as far as the model is concerned."""
    s = SAPMAPState()
    s.add_node(_node("DEV", host="a", ip="1.1.1.1", instno="0011112222"))
    s.add_node(_node("DEV", host="b", ip="2.2.2.2", instno="0033334444"))
    reloaded = SAPMAPState.from_dict(s.to_dict())
    assert sorted(reloaded.nodes) == ["DEV", "DEV#4444"]
    assert reloaded.nodes["DEV#4444"].installation_number == "0033334444"


# ---------------------------------------------------------------------------
# Merge doesn't clobber pwned/loot state on the survivor
# ---------------------------------------------------------------------------

def test_merge_preserves_survivor_pwned_flag_and_creds():
    from sapmap_models import Credentials
    s = SAPMAPState()
    first = _node("DEV", host="dev", ip="10.0.0.1")
    first.pwned = True
    first.credentials.append(Credentials(
        username="SAPMAP00", password="pw", client="000", verified=True))
    s.add_node(first)
    # Re-scan brings fresh node with no loot but same hostname
    s.add_node(_node("DEV", host="dev", ip="10.0.0.1"))
    survivor = s.nodes["DEV"]
    assert survivor.pwned is True
    assert len(survivor.credentials) == 1
    assert survivor.credentials[0].username == "SAPMAP00"
