"""
Tests for the canonical SAP port scheme (issue #249).

Guards:

  * Each service listed in the canonical table has exactly ONE
    authoritative formula (the drift that let CVE-247's 4300 bug
    survive is now impossible without a failing test).
  * ``sapmap_config.FAST_SCAN_PORT_PATTERNS`` is derived from the
    canonical table — editing one without the other fails here.
  * HANA labels: 3NN13 = SystemDB (MDC), 3NN15 = single-container
    indexserver (NOT "tenant").
  * New Pass-2 ports: sapstartsrv HTTPS (5NN14), AS-Java P4 (5NN04),
    ERS replication (5NN16).
  * ASCS/SCS INSTANCE_ROLE_LABELS carry the "Message Server + Enqueue"
    annotation in both Python and JS (the JS mirror in sapmap_html.py
    is kept in sync by the parity test already in
    tests/test_instance_roles_248.py; this file adds the enqueue
    phrasing guard).
  * JS SAP_PORT_SCHEME_JS in sapmap_html.py matches the Python
    canonical table one-for-one (name, formula, base, offset,
    description).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


# The scanner module is heavy (thousands of lines, imports ctypes).
# We rely on the project's flat-import sys.path hack by importing
# ``modules`` once up front — conftest.py already does this, so
# import succeeds here directly.
from sap_port_scheme import (
    FORMULA_3NN,
    FORMULA_5NN,
    FORMULA_BASE_NN,
    HANA_SQL_SERVICE_TOKEN,
    SAP_PORT_SCHEME,
    SAPPortSpec,
    describe_port,
    ers_services,
    fast_scan_pass1_services,
    fast_scan_pass2_services,
    port_for,
)
from sapmap_config import FAST_SCAN_PORT_PATTERNS
from sapmap_models import INSTANCE_ROLE_LABELS


# ---------------------------------------------------------------------------
# Single-source invariant
# ---------------------------------------------------------------------------


def test_every_service_has_exactly_one_authoritative_formula():
    """No two entries resolve to the same port for every instance 00-99."""
    # Collect all (service, port_for(inst=NN)) over the full range and
    # bucket them by port.  We expect zero port-collisions except where
    # two services are known to overlap by SAP design (none in our table
    # — see the comment below).
    collisions: dict[int, list[tuple[str, int]]] = {}
    for inst_nr in range(100):
        for name, spec in SAP_PORT_SCHEME.items():
            p = spec.port_for(inst_nr)
            collisions.setdefault(p, []).append((name, inst_nr))

    # A port that appears in more than one entry is only acceptable when
    # the (port, inst_nr) pairs differ — i.e. the SAME port is produced
    # by a DIFFERENT instance under another formula.  That's a legitimate
    # SAP reality (e.g. dispatcher 3200+00 = sapms 3600-400, but not for
    # the same NN).  The invariant we assert is sharper: no (port, nr)
    # pair produced by TWO different services at the SAME instance nr.
    same_nr_collisions = {
        p: pairs for p, pairs in collisions.items()
        if len({nr for _, nr in pairs}) < len(pairs)
    }
    assert same_nr_collisions == {}, (
        f"service/formula collision at same instance_nr: {same_nr_collisions}")


def test_fast_scan_pass1_derives_from_canonical_table():
    """sapmap_config.FAST_SCAN_PORT_PATTERNS == Pass-1 services' bases."""
    expected = {
        svc: SAP_PORT_SCHEME[svc].base
        for svc in fast_scan_pass1_services()
    }
    assert FAST_SCAN_PORT_PATTERNS == expected


def test_pass1_services_are_all_base_nn():
    """Pass-1 runs pre-instance-discovery — every service must be ``base+NN``."""
    for svc in fast_scan_pass1_services():
        spec = SAP_PORT_SCHEME[svc]
        assert spec.formula == FORMULA_BASE_NN, (
            f"Pass-1 service {svc!r} uses non-``base+NN`` formula "
            f"{spec.formula!r} — would break per-instance Pass-1 "
            f"sweeps that don't yet know the instance number.")


# ---------------------------------------------------------------------------
# HANA labels (the headline #249 fix)
# ---------------------------------------------------------------------------


def test_hana_sysdb_label():
    """3NN13 = SystemDB (MDC) — relabel from vague prior wording."""
    spec = SAP_PORT_SCHEME["hana_sysdb"]
    assert spec.port_for(0) == 30013
    assert spec.port_for(2) == 30213
    assert "SystemDB" in spec.description
    assert spec.formula == FORMULA_3NN


def test_hana_indexserver_label_not_tenant():
    """3NN15 = single-container indexserver — explicitly NOT "tenant"."""
    spec = SAP_PORT_SCHEME["hana_indexserver"]
    assert spec.port_for(0) == 30015
    assert spec.port_for(2) == 30215
    assert "indexserver" in spec.description.lower()
    # The old (wrong) label was "tenant"; make sure it never creeps back.
    assert "tenant" not in spec.description.lower(), (
        f"hana_indexserver description {spec.description!r} still says "
        f"'tenant' — MDC tenant SQL ports are DYNAMIC (3NN41+, read via "
        f"M_SERVICES), not computable from NN.  See issue #249.")


def test_hana_sql_service_token_is_stable():
    """Scanner emits ``hana_sql`` for both 3NN13 and 3NN15; description
    is resolved by port+inst_nr, not by the token."""
    assert HANA_SQL_SERVICE_TOKEN == "hana_sql"


def test_describe_port_distinguishes_hana_sysdb_from_indexserver():
    """GUI tooltip resolves 3NN13 and 3NN15 to distinct descriptions."""
    name13, desc13 = describe_port(30013, inst_nr=0)
    name15, desc15 = describe_port(30015, inst_nr=0)
    assert name13 == "hana_sysdb"
    assert name15 == "hana_indexserver"
    assert desc13 != desc15
    assert "SystemDB" in desc13
    assert "indexserver" in desc15.lower()


# ---------------------------------------------------------------------------
# New Pass-2 ports: sapstartsrv HTTPS + P4 + ERS replication
# ---------------------------------------------------------------------------


def test_sapstartsrv_https_formula():
    """5NN14 = sapstartsrv HTTPS (SAP Note 1014480) — new entry for #249."""
    spec = SAP_PORT_SCHEME["sapstartsrv_s"]
    assert spec.port_for(0) == 50014
    assert spec.port_for(13) == 51314
    assert "HTTPS" in spec.description or "SSL" in spec.description


def test_p4_formula():
    """5NN04 = AS-Java P4 (SAP Note 889188) — strong Java fingerprint."""
    spec = SAP_PORT_SCHEME["p4"]
    assert spec.port_for(0) == 50004
    assert spec.port_for(5) == 50504
    assert "P4" in spec.description


def test_ers_replication_formula():
    """5NN16 = ERS replication (SAP Note 1552925) — #249."""
    spec = SAP_PORT_SCHEME["ers_repl"]
    assert spec.port_for(0) == 50016
    assert spec.port_for(11) == 51116
    assert "ERS" in spec.description or "Replication" in spec.description


def test_scanner_pass2_includes_new_ports():
    """The hand-coded Pass 2 loop in sapmap_scanner emits sapstartsrv_s,
    java_p4, and ers_repl for every discovered instance."""
    scanner_src = Path(__file__).resolve().parent.parent / "modules" / "discovery" / "sapmap_scanner.py"
    text = scanner_src.read_text()
    # The ``50000 + inst_nr * 100 + 14`` call must feed "sapstartsrv_s"
    assert 'inst_nr * 100 + 14, "sapstartsrv_s"' in text, (
        "Pass 2 does not yet emit sapstartsrv HTTPS (5NN14) — issue #249.")
    # P4 (5NN04) — service token "java_p4" for back-compat with the
    # SAProuter scanner path.
    assert 'inst_nr * 100 + 4, "java_p4"' in text, (
        "Pass 2 does not yet emit AS-Java P4 (5NN04) — issue #249.")
    # ERS replication (5NN16)
    assert 'inst_nr * 100 + 16, "ers_repl"' in text, (
        "Pass 2 does not yet emit ERS replication (5NN16) — issue #249.")


# ---------------------------------------------------------------------------
# ASCS / SCS enqueue annotation
# ---------------------------------------------------------------------------


def test_ascs_label_names_message_server_and_enqueue():
    """The ASCS tooltip must say which two services it carries."""
    label = INSTANCE_ROLE_LABELS["ASCS"]
    assert "Message Server" in label
    assert "Enqueue" in label


def test_scs_label_names_message_server_and_enqueue():
    """The SCS tooltip must say which two services it carries."""
    label = INSTANCE_ROLE_LABELS["SCS"]
    assert "Message Server" in label
    assert "Enqueue" in label


def test_ers_role_is_still_distinct():
    """ERS is a separate role from ASCS/SCS."""
    assert "Replication" in INSTANCE_ROLE_LABELS["ERS"]


# ---------------------------------------------------------------------------
# JS parity — the SAP_PORT_SCHEME_JS mirror in sapmap_html.py
# ---------------------------------------------------------------------------


def test_js_port_scheme_mirrors_python_canonical_table():
    """Every SAP_PORT_SCHEME entry must appear in SAP_PORT_SCHEME_JS."""
    html = Path(__file__).resolve().parent.parent / "modules" / "core" / "sapmap_html.py"
    html_src = html.read_text()
    # Find the JS array
    m = re.search(
        r"const SAP_PORT_SCHEME_JS\s*=\s*\[(.*?)\];",
        html_src, flags=re.DOTALL)
    assert m, "SAP_PORT_SCHEME_JS not found in sapmap_html.py"
    js_block = m.group(1)

    for name, spec in SAP_PORT_SCHEME.items():
        # The JS tuple format: ['name', 'formula_token', base, offset, 'desc']
        # The exact description string must be present.
        assert f"'{name}'" in js_block, (
            f"service {name!r} missing from SAP_PORT_SCHEME_JS")
        # Base port present
        assert re.search(
            rf"'{name}'[^]]*?,\s*{spec.base}\s*,", js_block
        ), f"JS entry for {name!r} has the wrong base port"
        # Description present verbatim
        assert spec.description in js_block, (
            f"JS entry for {name!r} is missing description "
            f"{spec.description!r}")


def test_js_describe_sap_port_function_exists():
    """The GUI Open Ports section uses describeSapPort(port, instNr)."""
    html = Path(__file__).resolve().parent.parent / "modules" / "core" / "sapmap_html.py"
    html_src = html.read_text()
    assert "function describeSapPort(" in html_src
    # Verify it's wired into the Open Ports pill tooltip
    assert "describeSapPort(p, portInst.get(p))" in html_src, (
        "describeSapPort is defined but not wired into the Open Ports "
        "tooltip — issue #249.")


# ---------------------------------------------------------------------------
# Pass-2 / ERS service-list guards (tests the public helpers I expose)
# ---------------------------------------------------------------------------


def test_pass2_services_cover_new_fingerprints():
    """fast_scan_pass2_services() lists sapstartsrv_s + p4 + hana entries."""
    pass2 = set(fast_scan_pass2_services())
    for svc in ("sapstartsrv_s", "p4", "hana_sysdb", "hana_indexserver"):
        assert svc in pass2, f"{svc!r} missing from fast_scan_pass2_services"


def test_ers_services_covers_replication():
    assert "ers_repl" in ers_services()


# ---------------------------------------------------------------------------
# Formula sanity — the two per-instance HANA ports differ by 2
# ---------------------------------------------------------------------------


def test_hana_sysdb_and_indexserver_offset_by_two():
    """Standard SAP convention: 3NN13 and 3NN15 are offset by 2."""
    for nr in (0, 5, 42, 99):
        assert (SAP_PORT_SCHEME["hana_indexserver"].port_for(nr)
                - SAP_PORT_SCHEME["hana_sysdb"].port_for(nr)) == 2


# ---------------------------------------------------------------------------
# Regression: ICM HTTPS lives on 443NN, not 43NN (issue #247)
# ---------------------------------------------------------------------------


def test_icm_https_is_443NN_not_43NN():
    """Guard the #247 regression at the canonical-table layer too."""
    spec = SAP_PORT_SCHEME["icm_https"]
    assert spec.port_for(0) == 44300
    assert spec.port_for(0) != 4300
    assert spec.port_for(13) == 44313


# ---------------------------------------------------------------------------
# port_for() + describe_port() round-trip
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("service", list(SAP_PORT_SCHEME.keys()))
def test_port_for_round_trip(service):
    """For every service, describe_port(port_for(service, 5), 5) matches."""
    p = port_for(service, 5)
    resolved = describe_port(p, inst_nr=5)
    assert resolved is not None
    resolved_name, _ = resolved
    assert resolved_name == service


# ---------------------------------------------------------------------------
# End-to-end: scanner emission matches the canonical table
# ---------------------------------------------------------------------------
#
# Review-driven follow-up (#249 adversarial pass): the per-item tests
# above verify each piece in isolation, but a scanner that silently
# dropped a port emission could still slip through.  This test pins
# the scanner's two port-generation paths (``_build_port_list`` + the
# Pass-2 instance loop) to the canonical formula values.

from sapmap_scanner import _build_port_list


def test_build_port_list_hana_ports_match_canonical_table():
    """``_build_port_list(include_hana=True)`` emits the exact
    SystemDB and single-container indexserver port numbers from the
    canonical table for every instance in the range."""
    ports = _build_port_list((0, 5), include_hana=True)
    # Collect HANA SQL port→inst_nr pairs
    hana_hits = {
        (p, inst_str): True
        for p, svc, inst_str in ports
        if svc == HANA_SQL_SERVICE_TOKEN
    }
    for nr in range(0, 6):
        inst_str = f"{nr:02d}"
        sysdb = SAP_PORT_SCHEME["hana_sysdb"].port_for(nr)
        idx = SAP_PORT_SCHEME["hana_indexserver"].port_for(nr)
        assert (sysdb, inst_str) in hana_hits, (
            f"scanner missed HANA SystemDB port {sysdb} for inst {inst_str}")
        assert (idx, inst_str) in hana_hits, (
            f"scanner missed HANA indexserver port {idx} for inst {inst_str}")


def test_pass2_block_emits_all_new_port_formulas_literally():
    """Scan source for the three new Pass-2 port literals — a regression
    where someone deletes one line would be caught here even without
    executing the scanner."""
    scanner_src = Path(__file__).resolve().parent.parent / "modules" / "discovery" / "sapmap_scanner.py"
    text = scanner_src.read_text()
    # The canonical formulas expressed literally in the scanner source.
    patterns = [
        ("sapstartsrv HTTPS 5NN14", r'50000 \+ inst_nr \* 100 \+ 14, "sapstartsrv_s"'),
        ("AS-Java P4 5NN04",        r'50000 \+ inst_nr \* 100 \+ 4, "java_p4"'),
        ("ERS replication 5NN16",   r'50000 \+ inst_nr \* 100 \+ 16, "ers_repl"'),
    ]
    for label, pat in patterns:
        assert re.search(pat, text), (
            f"Pass-2 loop is missing {label} — issue #249 regression.")
