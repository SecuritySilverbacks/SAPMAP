"""
Canonical SAP per-instance port scheme (issue #249).

Single source of truth for SAP port formulas. SAPMAP previously carried
the same per-instance formulas in three places:

  * ``modules/core/sapmap_config.FAST_SCAN_PORT_PATTERNS`` — fast-scan Pass 1
  * ``modules/discovery/sapmap_scanner`` — Pass 2 + HANA + Java ports
  * ``SAPology.sapology.SAP_PORTS`` — the external deep-scan tool

The drift across those three is how the ICM-HTTPS ``4300 → 44300`` bug
(issue #247) survived uncaught. This table is the authoritative
reference; the fast scanner is kept in sync via
``tests/test_port_scheme_249.py`` (one failing test if ``sapmap_config``
drifts). SAPology stays independent (separate repo + install story) but
its ``SAP_PORTS`` dict is structurally equivalent and covered by a
cross-tree parity test when SAPology is installed next to this tree.

Every entry carries a SAP Help / Note citation so future edits stay
grounded. The canonical reference is SAP Help "TCP/IP Ports of All SAP
Products" (``ports.pdf``).

Port-number naming (as SAP documents it):

    NN         = instance number, 00-99
    ``base+NN`` = fixed ``base`` plus the instance number
    ``5NN<X>``  = 50000 + NN * 100 + X  (the ``5XX`` series)
    ``3NN<X>``  = 30000 + NN * 100 + X  (HANA)

See also: the non-formula fixed ports (SAP Host Agent 1128/1129,
SAProuter 3299, Content Server 1090/1091, BO 6400, ...). They do not
live here because they are not per-instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Citations
# ---------------------------------------------------------------------------

# "TCP/IP Ports of All SAP Products" — the authoritative port table.
CITE_SAP_HELP_TCP_IP = (
    "https://help.sap.com/docs/SLTOOLSET/"
    "d78e97ea0e3b4e9db5f49f3aa6f1ef98/ports.pdf"
)
# sapstartsrv as the SAP management agent — defines 5NN13 / 5NN14.
CITE_SAP_NOTE_1014480 = "SAP Note 1014480 (sapstartsrv as SAP management agent)"
# AS Java P4 RMI protocol — defines 5NN04.
CITE_SAP_NOTE_889188 = "SAP Note 889188 (AS Java P4 protocol)"
# Enqueue Replication Server — defines 5NN16 for ERS replication.
CITE_SAP_NOTE_1552925 = "SAP Note 1552925 (Enqueue Replication Server)"


# ---------------------------------------------------------------------------
# Port spec
# ---------------------------------------------------------------------------

# Formula tokens. These are the only values ``SAPPortSpec.formula`` can
# take; other code branches on them.
FORMULA_BASE_NN = "base+NN"           # base + NN
FORMULA_5NN = "50000+NN*100+offset"   # 5XX series: 50000 + NN*100 + offset
FORMULA_3NN = "30000+NN*100+offset"   # HANA: 30000 + NN*100 + offset


@dataclass(frozen=True)
class SAPPortSpec:
    """A per-instance SAP port formula.

    ``port_for(inst_nr) -> int`` resolves the formula; ``description`` is
    the human label for GUI / report; ``citation`` is where it comes
    from.  Attributes are immutable so a spec can be hashed and shared.
    """
    name: str
    description: str
    formula: str
    base: int
    offset: int
    citation: str

    def port_for(self, inst_nr: int) -> int:
        """Resolve the formula to a port number for ``inst_nr`` (0-99)."""
        if self.formula == FORMULA_BASE_NN:
            return self.base + inst_nr
        if self.formula == FORMULA_5NN:
            return 50000 + inst_nr * 100 + self.offset
        if self.formula == FORMULA_3NN:
            return 30000 + inst_nr * 100 + self.offset
        raise ValueError(f"unknown formula: {self.formula!r}")


# ---------------------------------------------------------------------------
# The canonical table
# ---------------------------------------------------------------------------
#
# Order matches the SAP Help "ports.pdf" grouping:
#   (1) classic 3XXX channels (DIAG / RFC / MS),
#   (2) ICM HTTP(S),
#   (3) sapstartsrv / SAPControl,
#   (4) AS-Java (J2EE + P4),
#   (5) Enqueue Replication,
#   (6) HANA SQL.
#

SAP_PORT_SCHEME: Dict[str, SAPPortSpec] = {
    # ------------------------------------------------------------------ 3XXX
    "dispatcher": SAPPortSpec(
        name="dispatcher",
        description="SAP Dispatcher (DIAG, sapdp<NN>)",
        formula=FORMULA_BASE_NN, base=3200, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    "gateway": SAPPortSpec(
        name="gateway",
        description="SAP Gateway (plaintext RFC, sapgw<NN>)",
        formula=FORMULA_BASE_NN, base=3300, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    "gateway_snc": SAPPortSpec(
        name="gateway_snc",
        description="SAP Gateway (SNC-wrapped RFC, sapgw<NN>s)",
        formula=FORMULA_BASE_NN, base=4800, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    "sapms": SAPPortSpec(
        name="sapms",
        description="Message Server — external (sapms<SID>; SAP GUI logon-group broadcast)",
        formula=FORMULA_BASE_NN, base=3600, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    "ms_internal": SAPPortSpec(
        name="ms_internal",
        description="Message Server — internal (rdisp/msserv_internal; betrusted vector)",
        formula=FORMULA_BASE_NN, base=3900, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    "ms_http": SAPPortSpec(
        name="ms_http",
        description="Message Server HTTP (logon-group browse; /msgserver/*)",
        formula=FORMULA_BASE_NN, base=8100, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),

    # ------------------------------------------------------------------ ICM
    "icm_http": SAPPortSpec(
        name="icm_http",
        description="ICM HTTP",
        formula=FORMULA_BASE_NN, base=8000, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    # ICM HTTPS is 443NN (44300 + NN).  43NN / 4300 is HANA's bundled Web
    # Dispatcher HTTPS range — a different service.  See issue #247.
    "icm_https": SAPPortSpec(
        name="icm_https",
        description="ICM HTTPS",
        formula=FORMULA_BASE_NN, base=44300, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),

    # ------------------------------------------------------------------ 5XX series
    "sapstartsrv": SAPPortSpec(
        name="sapstartsrv",
        description="sapstartsrv / SAPControl SOAP (HTTP)",
        formula=FORMULA_5NN, base=50000, offset=13,
        citation=CITE_SAP_NOTE_1014480,
    ),
    "sapstartsrv_s": SAPPortSpec(
        name="sapstartsrv_s",
        description="sapstartsrv / SAPControl SOAP (HTTPS)",
        formula=FORMULA_5NN, base=50000, offset=14,
        citation=CITE_SAP_NOTE_1014480,
    ),
    "j2ee_http": SAPPortSpec(
        name="j2ee_http",
        description="AS Java HTTP (ICM/J2EE)",
        formula=FORMULA_5NN, base=50000, offset=0,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    "j2ee_https": SAPPortSpec(
        name="j2ee_https",
        description="AS Java HTTPS (ICM/J2EE)",
        formula=FORMULA_5NN, base=50000, offset=1,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    # P4 is RMI; its presence is a strong AS-Java fingerprint — ABAP
    # instances do not open 5NN04.
    "p4": SAPPortSpec(
        name="p4",
        description="AS Java P4 (RMI / JNDI)",
        formula=FORMULA_5NN, base=50000, offset=4,
        citation=CITE_SAP_NOTE_889188,
    ),
    # ERS replication port.  The standalone-enqueue server listens here
    # for the replica's lock-table catch-up stream.  No single canonical
    # port for the enqueue server itself exists (SAP splits 32NN vs
    # 39NN depending on version / profile), so we only model ERS
    # replication — see the enqueue note on the ASCS/SCS entries.
    "ers_repl": SAPPortSpec(
        name="ers_repl",
        description="Enqueue Replication (ERS replica catch-up)",
        formula=FORMULA_5NN, base=50000, offset=16,
        citation=CITE_SAP_NOTE_1552925,
    ),

    # ------------------------------------------------------------------ HANA
    # 3NN13 = SystemDB (MDC) — the system-database SQL endpoint.  On a
    # single-container install this port is not used; on MDC it hosts the
    # SystemDB indexserver's public SQL.
    "hana_sysdb": SAPPortSpec(
        name="hana_sysdb",
        description="HANA SQL — SystemDB (MDC) / indexserver on single-container",
        formula=FORMULA_3NN, base=30000, offset=13,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
    # 3NN15 = single-container indexserver.  This is NOT a tenant port —
    # true MDC tenant SQL ports are DYNAMIC (typically 3NN41+, assigned
    # by HANA, readable via ``M_SERVICES``) and cannot be computed from
    # the instance number.  Previous SAPMAP/SAPology labels called this
    # "tenant", which was wrong; see issue #249.
    "hana_indexserver": SAPPortSpec(
        name="hana_indexserver",
        description="HANA SQL — single-container indexserver (or MDC compat endpoint)",
        formula=FORMULA_3NN, base=30000, offset=15,
        citation=CITE_SAP_HELP_TCP_IP,
    ),
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

# Service-token used in the scanner's open_ports map for every HANA SQL
# port.  The per-port role (sysdb vs indexserver) is resolved by the
# port number, not by the token.  Kept here so callers do not hard-code
# the string.
HANA_SQL_SERVICE_TOKEN = "hana_sql"


def port_for(service: str, inst_nr: int) -> int:
    """Return the per-instance port for ``service`` + ``inst_nr``.

    Raises ``KeyError`` for an unknown service name.
    """
    spec = SAP_PORT_SCHEME.get(service)
    if spec is None:
        raise KeyError(f"unknown SAP service: {service!r}")
    return spec.port_for(inst_nr)


def describe_port(port: int, inst_nr: Optional[int] = None) -> Optional[Tuple[str, str]]:
    """Return ``(canonical_service_name, description)`` for ``port``.

    When ``inst_nr`` is given the lookup is exact.  When it is ``None``
    we try every instance 00-99; the first match wins.  This is used by
    GUI tooltips when the open_ports map does not carry the instance
    number on the port itself.

    Returns ``None`` when nothing in the table matches ``port``.
    """
    if inst_nr is not None:
        for name, spec in SAP_PORT_SCHEME.items():
            if spec.port_for(inst_nr) == port:
                return name, spec.description
        return None
    for nr in range(100):
        m = describe_port(port, nr)
        if m:
            return m
    return None


def fast_scan_pass1_services() -> Tuple[str, ...]:
    """Return the service names included in fast-scan Pass 1.

    Pass 1 runs on every host before any instance has been identified,
    so it must stay small.  Every service in this tuple is also an
    entry in ``SAP_PORT_SCHEME`` — ``sapmap_config.FAST_SCAN_PORT_PATTERNS``
    is derived from it.
    """
    return ("dispatcher", "gateway", "sapms")


def fast_scan_pass2_services() -> Tuple[str, ...]:
    """Return the service names probed in fast-scan Pass 2 (per instance).

    Pass 2 fires once an instance has been discovered via Pass 1.  HANA
    SQL and the 5XX-series ports live here so we only probe them for
    instances we have already confirmed.
    """
    return (
        "gateway_snc",
        "ms_internal",
        # HANA SQL — both ports stay on, but their labels at display
        # time distinguish SystemDB (3NN13) from indexserver (3NN15).
        "hana_sysdb",
        "hana_indexserver",
        # AS-Java fingerprints.
        "j2ee_http",
        "j2ee_https",
        "p4",
        # sapstartsrv HTTPS — the HTTP side (5NN13) is already covered
        # by the quick-probe sweep in Pass 1.
        "sapstartsrv_s",
    )


def ers_services() -> Tuple[str, ...]:
    """Return the service names probed when an ERS instance exists.

    Gated on an instance whose ``instance_type == "ERS"`` — we do not
    pay for an extra 5NN16 probe on every host.
    """
    return ("ers_repl",)
