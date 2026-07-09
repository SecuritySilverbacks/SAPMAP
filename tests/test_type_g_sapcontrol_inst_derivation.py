"""Type-G SAPControl.CGI destinations: port→instance derivation.

Pinned bug (2026-07-09): a Type-G destination
``https://192.168.2.192:50213/SAPControl.CGI`` was being materialised as
Inst 00 in the "SAP System" modal, AND a duplicate SID (``SJJ1``) was
appearing on the map next to the existing ``SJJ`` box.

Root cause: ``_parse_rfcdes_http_options`` doesn't populate
``target_instance_nr`` (Type-G RFCOPTIONS has no dedicated field for
it — the URL is the authoritative source).  The ping loop in
``sapmap_gui.py`` defaulted ``inst = "00"`` and only knew how to derive
instance from the ``8000-8999`` port range, missing the SAPControl
family (``5NN13/5NN14``) entirely.  That misfire cascaded:

  1. ``find_node_by_host(hostname="192.168.2.192", instance_nr="00")``
     returned None because the existing SJJ node carries Inst 02
  2. A new SID collision-suffix (``SJJ1``) was created for the same
     physical host
  3. Its InstanceInfo went in with ``instance_nr="00"``

Fix: shared helper ``_derive_inst_from_url_port`` in
``sapmap_gui.py`` — same formula as ``materialise_type_g_target`` in
``sapmap_models.py``.

These tests pin the derivation directly (unit) and the end-to-end
resolution via ``find_node_by_host`` (integration).
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
from sapmap_models import SAPNode, InstanceInfo, SAPMAPState


# ---------------------------------------------------------------------------
# Unit tests: the pure port→instance derivation
# ---------------------------------------------------------------------------

def test_derive_inst_from_sapcontrol_https():
    """Port 50213 → instance 02 (SAPControl HTTPS on inst 02)."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port(
        "https://192.168.2.192:50213/SAPControl.CGI") == "02"


def test_derive_inst_from_sapcontrol_http():
    """Port 50014 → instance 00 (SAPControl HTTP on inst 00)."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port(
        "http://host:50014/SAPControl.CGI") == "00"


def test_derive_inst_from_java_http():
    """Port 50100 → instance 01 (Java HTTP on inst 01)."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port(
        "http://host:50100/") == "01"


def test_derive_inst_from_abap_icm_http():
    """Port 8002 → instance 02 (ABAP ICM HTTP on inst 02).

    Regression against the old broken formula ``(port-8000)//100`` which
    mapped 8002 → 00 despite ICM ports being 80NN with NN = instance.
    """
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port(
        "http://host:8002/sap/bc/") == "02"


def test_derive_inst_from_abap_icm_https():
    """Port 44302 → instance 02 (ABAP ICM HTTPS on inst 02)."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port(
        "https://host:44302/sap/bc/") == "02"


def test_derive_inst_returns_empty_for_unknown_port():
    """Non-SAP ports return "" — caller keeps its default (usually
    "00").  Prevents mis-attributing a random :443 or :80 destination
    to instance 00 on the map."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port("https://host:443/") == ""
    assert _derive_inst_from_url_port("http://host/") == ""
    assert _derive_inst_from_url_port("https://host:1234/") == ""


def test_derive_inst_handles_bad_url():
    """Malformed URL doesn't blow up — returns "" so the caller falls
    through cleanly."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port
    assert _derive_inst_from_url_port("") == ""
    assert _derive_inst_from_url_port("not://a valid url") == ""


# ---------------------------------------------------------------------------
# Integration test: end-to-end via find_node_by_host
# ---------------------------------------------------------------------------

def test_existing_sjj_matched_by_derived_instance():
    """The critical case: an SJJ node on 192.168.2.192 carries Inst 02,
    and a Type-G destination points at ``:50213/SAPControl.CGI``.  With
    the fix, ``inst`` derives to "02" BEFORE ``find_node_by_host``, so
    the existing SJJ matches and no duplicate SJJ1 is created."""
    from modules.core.sapmap_gui import _derive_inst_from_url_port

    state = SAPMAPState()
    state.nodes["SJJ"] = SAPNode(
        sid="SJJ",
        ip="192.168.2.192",
        instances=[InstanceInfo(instance_nr="02", ip="192.168.2.192")])

    # Simulate the ping-loop derivation for a fresh Type-G conn
    url = "https://192.168.2.192:50213/SAPControl.CGI"
    derived = _derive_inst_from_url_port(url)
    assert derived == "02", (
        "port 50213 must map to instance 02; anything else and "
        "find_node_by_host would miss SJJ and mint SJJ1")

    # Now the host+inst lookup lands on the existing SJJ
    hit = state.find_node_by_host(
        hostname="192.168.2.192", ip="192.168.2.192",
        instance_nr=derived)
    assert hit is not None, (
        "SJJ must resolve via find_node_by_host once inst='02' is "
        "supplied — this is the exact call the ping loop makes")
    assert hit.sid == "SJJ"


def test_wrong_inst_would_miss_sjj_and_mint_dup():
    """Negative pin: proves the pre-fix behaviour actually produced
    the duplicate.  Without the port heuristic, ``inst`` stays "00"
    and ``find_node_by_host`` returns None because SJJ carries Inst
    02.  If this test ever starts finding the node with inst='00',
    something in the model relaxed and the fix could regress
    invisibly."""
    state = SAPMAPState()
    state.nodes["SJJ"] = SAPNode(
        sid="SJJ",
        ip="192.168.2.192",
        instances=[InstanceInfo(instance_nr="02", ip="192.168.2.192")])
    hit = state.find_node_by_host(
        hostname="192.168.2.192", ip="192.168.2.192",
        instance_nr="00")
    assert hit is None, (
        "pre-fix bug reproducer: SJJ has Inst 02, looking up with "
        "inst='00' MUST return None so the pipeline knows to create "
        "a new node (which is exactly why the fix derives inst from "
        "the URL port before this call)")
