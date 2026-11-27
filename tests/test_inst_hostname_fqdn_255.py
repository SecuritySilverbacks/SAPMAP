"""Issue #255 follow-up — why the kernel-793 CPIC ``long_lu`` tier-2 floor
(``inst.ip``) is the correct final state for the RFC-ping producer, and must
NOT be "upgraded" to a tier-1 ``inst.hostname`` there.

#255 part 3 (PR #257) gave ``_gw_hostname_for_port`` the precedence
``inst.hostname → inst.ip (when != node.ip) → node.hostname → inst.ip →
node.ip``.  Tier-1 (``inst.hostname``) only fires when a *producer* populated
it.  The two producers that can reliably know a per-instance FQDN — the
Message-Server app-server import (``sapmap_gui._import_appserver_instances``)
and the SAPology deep-scan bridge (``sapmap_scanner._sapology_system_to_node``)
— already thread it, so tier-1 is correct THERE.

An audit of every ``InstanceInfo`` producer looked for a further site that
could thread a per-instance hostname.  ``sapmap_autopwn._correct_node_http``
appeared to be one (it appends a gateway-bearing instance to an existing,
possibly multi-host node and has ``http_info['hostname']`` in hand).  Threading
it would be a **regression**, and these tests pin why:

  ``ping_rfc_destination`` sources the hostname from DEST_CHECK_CONNECTION
  (CONNECTION_PROPERTIES.RFCHOST — one RFC logon) but the ip + instance_nr
  from a SEPARATE RFC_GET_SYSTEM_INFO logon (RFCSI_EXPORT.RFCIPADDR / RFCDEST).
  On a load-balanced / group-logon Type-3 destination the message server can
  balance those two logons to DIFFERENT app servers of the SAME SID — so the
  hostname can name a different box than the ip and 33NN gateway port recorded
  for the instance.  Because ip and instance_nr are co-sourced (always the
  owning box), leaving inst.hostname empty makes the reader use tier-2
  (inst.ip — always correct) instead of a tier-1 hostname that could be the
  wrong box's name and silently invalidate the kernel-793 conv_id.

So: tier-1 is right when a producer can reliably supply the owning instance's
name (MS-import / SAPology); tier-2 (inst.ip) is the correct floor when it
cannot (the RFC-ping path).  These tests guard both halves.
"""
import os

from sapmap_models import SAPNode, InstanceInfo
import sapmap_autopwn
import sapmap_exploit as X


_MS_HOST = "ascs.corp.example"      # central-services / node-level host
_MS_IP = "10.0.0.1"
_APP_IP = "10.0.0.5"                 # the box that RFCSI_EXPORT (ip+inst_nr) named
_OTHER_FQDN = "app99.corp.example"   # a DIFFERENT box's name (the load-balanced hazard)


def _multihost_node():
    """Node whose node.ip is the central-services box carrying instance 00;
    _correct_node_http will append instance 04 from a destination ping."""
    return SAPNode(
        sid="SB1",
        ip=_MS_IP,
        hostname=_MS_HOST,
        instances=[InstanceInfo(instance_nr="00", ip=_MS_IP,
                                ports={3300: "gateway", 3200: "dispatcher"})],
    )


def test_correct_node_http_does_not_thread_hostname():
    """Even when the ping handed us a hostname, the appended instance must NOT
    carry it — the hostname (RFCHOST logon) may name a different app server
    than the ip/instance_nr (RFCSI_EXPORT logon) on a load-balanced dest."""
    n = _multihost_node()
    sapmap_autopwn._correct_node_http(
        n, {"instance_nr": "04", "ip": _APP_IP, "hostname": _OTHER_FQDN})
    added = [i for i in n.instances if i.instance_nr == "04"]
    assert added, "probed instance 04 should have been appended"
    assert added[0].hostname == "", (
        "inst.hostname must stay empty so the long_lu uses the co-sourced "
        "inst.ip, not a possibly-wrong-box hostname")


def test_correct_node_http_longlu_uses_cosourced_inst_ip_not_hostname():
    """The kernel-793 long_lu for the appended instance's gateway resolves to
    its co-sourced ip (always the owning box), never the ping hostname."""
    n = _multihost_node()
    sapmap_autopwn._correct_node_http(
        n, {"instance_nr": "04", "ip": _APP_IP, "hostname": _OTHER_FQDN})
    # instance 04 owns gateway 3304 (int("33"+"04"))
    assert X._gw_hostname_for_port(n, 3304) == _APP_IP
    assert X._gw_hostname_for_port(n, 3304) != _OTHER_FQDN
    # the primary instance 00 still resolves to the central-services host
    assert X._gw_hostname_for_port(n, 3300) == _MS_HOST


def test_correct_node_http_does_not_pass_hostname_in_source():
    """Guard against reintroduction: the InstanceInfo built in
    _correct_node_http must not pass hostname=http_info[...], and the rationale
    comment must remain."""
    src_path = os.path.join(os.path.dirname(__file__), "..",
                            "modules", "exploitation", "sapmap_autopwn.py")
    with open(src_path, "r", encoding="utf-8") as fh:
        src = fh.read()
    assert 'hostname=http_info' not in src, (
        "threading the ping hostname onto the appended instance regresses "
        "load-balanced Type-3 destinations — see this test's docstring")
    assert "DELIBERATELY not threading hostname" in src, (
        "the rationale comment at _correct_node_http must stay so the hazard "
        "is not forgotten")


def test_reliable_producer_tier1_hostname_is_honoured():
    """Positive half: when a producer CAN reliably supply the owning
    instance's name (MS-import / SAPology bridge construct InstanceInfo with a
    trustworthy per-instance hostname), tier-1 returns it — the #255-part-3
    fix still works where the hostname is sound."""
    n = SAPNode(
        sid="SB3", ip=_MS_IP, hostname=_MS_HOST,
        instances=[
            InstanceInfo(instance_nr="00", ip=_MS_IP, ports={3300: "gateway"}),
            # reliably-sourced per-instance hostname (e.g. MS app-server import)
            InstanceInfo(instance_nr="04", ip=_APP_IP, hostname="app04.corp.example",
                         ports={3304: "gateway"}),
        ],
    )
    assert X._gw_hostname_for_port(n, 3304) == "app04.corp.example"


def test_portless_instance_hostname_never_surfaced_by_gw_reader():
    """Why the portless producer sites (SAPControl identity-backfill, TMS/BTP
    seeds built with ports={}) were left unchanged: a portless instance is
    never iterated by _gw_hostname_for_port, so a hostname on it would be
    inert.  Pin that so nobody 'fixes' those sites believing it changes the
    long_lu."""
    n = SAPNode(
        sid="SB2", ip=_MS_IP, hostname=_MS_HOST,
        instances=[
            InstanceInfo(instance_nr="00", ip=_MS_IP, ports={3300: "gateway"}),
            InstanceInfo(instance_nr="04", ip=_APP_IP, hostname=_OTHER_FQDN,
                         ports={}),   # portless → never selected
        ],
    )
    assert X._gw_hostname_for_port(n, 3300) == _MS_HOST
    assert X._gw_hostname_for_port(n, 3304) == _MS_HOST
    assert X._gw_hostname_for_port(n, 3304) != _OTHER_FQDN
