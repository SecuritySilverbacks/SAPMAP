"""Issue #16 — distributed HANA dbhost for the GW SAPXPG user-create path.

The on-target hdbsql wrapper runs on the SAP *app server* (via unauth GW
SAPXPG RCE as <sid>adm).  Before this fix every hdbsql invocation was
hardcoded to ``-n localhost:<port>``, which only works when HANA is
co-located.  On a DISTRIBUTED HANA (DB on a separate host, e.g. a CAL
appliance) ``localhost`` connects to nothing, and SAPMAP — the remote
attacker — often can't resolve or reach the internal DB-host name over the
internet.

Fix: the wrapper discovers the DB host ON-TARGET from the SAP profile
(``SAPDBHOST`` in ``/usr/sap/<SID>/SYS/profile/*``, which the app server
always has locally) and builds an ordered connect-host list ``$HOSTS`` —
``localhost`` first (so a co-located 127.0.0.1-bound HANA is unaffected,
NO regression), then the discovered DB host.  Every hdbsql attempt loops
``$HOSTS``.

These tests pin the generated shell; live validation against a real
distributed HANA / CAL system is the deferred acceptance step the issue
calls for.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

import pytest

# sap_db_sql_writers <-> sapmap_exploit have a circular import; prime
# sapmap_exploit first (same as test_hana_hdbsql_probe).
import sapmap_exploit  # noqa: F401
from sap_db_sql_writers import (  # noqa: E402
    _build_hana_wrapper_script, _hana_dbhost_prelude_sh,
)


# --- the shared on-target dbhost-discovery prelude -------------------------

def test_prelude_greps_sapdbhost_from_profile():
    sh = _hana_dbhost_prelude_sh("NPL")
    # reads SAPDBHOST from the SAP profile dir for THIS sid
    assert "/usr/sap/NPL/SYS/profile/*" in sh
    assert "SAPDBHOST" in sh
    # anchored at line start (after optional whitespace) so a commented-out
    # '# SAPDBHOST = ...' line is not matched
    assert "'^[[:space:]]*SAPDBHOST[[:space:]]*='" in sh


def test_prelude_defaults_to_localhost_and_tries_it_first():
    sh = _hana_dbhost_prelude_sh("NPL")
    # $HOSTS always starts as localhost
    assert "HOSTS=localhost" in sh
    # the discovered host is appended AFTER localhost, and only when it is a
    # real, different value (never duplicates localhost)
    assert 'HOSTS="localhost $D"' in sh
    assert '[ "$D" != localhost ]' in sh


# --- the GW SAPXPG wrapper uses the prelude + host loop --------------------

def test_wrapper_embeds_dbhost_prelude():
    script = _build_hana_wrapper_script("A4H", "00")
    assert "SAPDBHOST" in script
    assert "/usr/sap/A4H/SYS/profile/*" in script


def test_wrapper_has_no_hardcoded_localhost_connect():
    """Every hdbsql invocation must go through the $HOSTS loop — no
    ``-n localhost:<port>`` hardcode may survive (that was the bug)."""
    script = _build_hana_wrapper_script("A4H", "00",
                                        probed_ports=[(30215, "x")])
    assert "-n localhost:" not in script, (
        "a hardcoded -n localhost: connect regresses distributed HANA")
    # connects use the loop variable instead
    assert "-n $_h:" in script
    assert "for _h in $HOSTS" in script


def test_wrapper_localhost_is_tried_before_discovered_dbhost():
    """Ordering guard: within the host loop localhost precedes the
    discovered DB host, so a co-located 127.0.0.1-bound HANA still wins."""
    sh = _hana_dbhost_prelude_sh("A4H")
    # the only construction of HOSTS with a second host keeps localhost first
    assert 'HOSTS="localhost $D"' in sh
    assert 'HOSTS="$D localhost"' not in sh


def test_wrapper_preserves_full_port_ladder():
    script = _build_hana_wrapper_script("IDE", "00", hdbsql_path="/x/hdbsql")
    # 3<NN>15 → SYSTEMDB 3<NN>13 tenant lookup → 3<NN>41, all still present
    assert "3${N}15" in script
    assert "3${N}13" in script
    assert "3${N}41" in script


def test_wrapper_probed_ports_run_first_via_R():
    """SAPMAP-proven-listening ports stay at the top of the ladder, now
    expressed through the R() helper (which itself loops $HOSTS)."""
    script = _build_hana_wrapper_script(
        "IDE", "00", probed_ports=[(30215, "3NN15"), (30213, "3NN13")])
    assert "R 30215" in script
    assert "R 30213" in script
    # probed ports precede the convention 3<NN>15 attempt
    assert script.index("R 30215") < script.index("R 3${N}15")


def test_wrapper_diagnostic_records_resolved_dbhost():
    script = _build_hana_wrapper_script("A4H", "00")
    assert "DBHOST=${D:-localhost}" in script


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh")
@pytest.mark.parametrize("kwargs", [
    {},
    {"hdbsql_path": "/x/hdbsql"},
    {"probed_ports": [(30215, "a"), (30013, "b")]},
])
def test_wrapper_is_valid_posix_sh(kwargs):
    """The generated wrapper must parse under /bin/sh -n for every code
    path (default runtime probe, supplied path, probed ports)."""
    script = _build_hana_wrapper_script("A4H", "00", **kwargs)
    fd, path = tempfile.mkstemp(suffix=".sh")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(script)
        proc = subprocess.run(["sh", "-n", path],
                              capture_output=True, text=True)
        assert proc.returncode == 0, (
            f"sh -n rejected the wrapper: {proc.stderr}")
    finally:
        os.unlink(path)
