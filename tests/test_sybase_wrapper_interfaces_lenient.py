#!/usr/bin/env python3
"""Regression tests for the Sybase wrapper's lenient interfaces parsing
(operator lab SM1 report 2026-10-09).

Symptom: GW SAPXPG + sybase writer confirmed OS-exec (whoami=sm1adm)
but the SQL insert groups all failed with:

    CT-LIBRARY error:
    ct_connect(): directory service layer: internal directory control
    layer error: Requested server name not found.
    SAPMAP:EXIT=255

Root cause: /sybase/SM1/interfaces had endpoint lines prefixed with
'#' (admin disabled interfaces-based discovery while keeping the
entries for reference).  isql -S SM1 found the SM1 header but no
usable endpoint and bailed.  SYBASE.csh init script carried no
DSQUERY setenv either (and csh-only installs can't be sourced from
our sh wrapper anyway), so neither path rescued the connection.

Fix: wrapper now rewrites the interfaces file to a session-tmp copy
via `sed "s/^#/<TAB>/"` and points isql at it with `-I <tmpfile>`.
Comment-prefixed endpoints get re-enabled for THIS invocation; the
target's interfaces file is unchanged.  '#' → TAB (not strip) because
Sybase's directory parser treats any line flush at column 0 as a new
server-name header — a stripped-but-unindented `master tcp ether host
port` would become a bogus server header and re-trigger the exact
ct_connect error we're fixing.  A leading TAB puts the endpoint line
at the standard Sybase indent.
"""
from __future__ import annotations

import re

import pytest

import modules  # noqa: F401 — registers package paths


def _import_writers_safely():
    """sap_db_sql_writers has a circular dep with sapmap_exploit that
    only resolves cleanly when sapmap_exploit is loaded first.
    Mirrors the helper in tests/test_evasion_tier3_foundation.py:2850
    so new Sybase tests don't re-stub the dance."""
    import sapmap_exploit  # noqa: F401 — primes the chain
    import sap_db_sql_writers as _w
    return _w


def _wrapper(sid: str = "SM1", pw: str = "", user: str = "sapsa") -> str:
    """Build the wrapper for assertions."""
    _w = _import_writers_safely()
    return _w._build_sybase_wrapper_script(
        sid, db_password=pw, db_user=user)


# ---------------------------------------------------------------------------
# Lenient interfaces plumbing — the actual fix
# ---------------------------------------------------------------------------

def test_wrapper_declares_iface_tmp_path():
    """Session-tmp interfaces copy lives under /tmp with a stable name
    so repeat invocations (test harness, multi-wave AutoPwn, operator
    rerun after a target-side change) don't accumulate garbage."""
    _w = _import_writers_safely()
    assert hasattr(_w, "_SYBASE_IFACE_PATH"), (
        "wrapper must export the tmp-interfaces path as a module "
        "constant so callers / tests can clean it up predictably")
    assert _w._SYBASE_IFACE_PATH.startswith("/tmp/"), (
        f"iface tmp path must land under /tmp (world-writable + "
        f"cleaned by OS); got {_w._SYBASE_IFACE_PATH!r}")


def test_wrapper_rewrites_hash_to_tab_in_interfaces_tmp():
    """Wrapper must replace a leading '#' on interfaces lines with a
    TAB (via a sed call that resolves $TAB from `printf '\\t'`) and
    write the result to the tmp path — this is the mechanism that
    rescues admin-disabled endpoints.  '#' → TAB (not strip!) because
    master/query entries must be indented, or Sybase's directory
    parser treats them as new server-name headers and ct_connect
    fails exactly as before the fix."""
    body = _wrapper()
    # TAB variable derived from `printf '\t'` — portable across every
    # /bin/sh variant (dash, busybox, ash) that doesn't honour the
    # bash-ism `sed 's/.../\t/'`.
    assert "TAB=\"$(printf '\\t')\"" in body, (
        "wrapper must resolve a literal TAB via printf '\\t' — a bare "
        "sed with \\t in the pattern isn't portable to dash/busybox")
    assert "sed \"s/^#/$TAB/\" \"$IFACE_SRC\" > \"$IFACE_TMP\"" in body, (
        "wrapper must sed-replace leading '#' with the TAB variable "
        "into IFACE_TMP — strip-only would leave master/query flush "
        "at col 0 and Sybase would treat them as new server-name "
        "headers")
    # Both the source + tmp paths must be variables (not hard-coded
    # in the sed command) so a future refactor can repoint them
    # without re-editing the regex.
    assert "IFACE_SRC=\"$SYBASE/interfaces\"" in body, (
        "wrapper must read interfaces from $SYBASE/interfaces "
        "(the SAP-ASE on-disk convention)")


def test_wrapper_sed_does_not_strip_hash_without_tab():
    """Regression pin: ship #126 shipped `sed 's/^#//'` which left
    master/query lines flush at col 0 — Sybase treated them as new
    server-name headers and ct_connect still errored.  This test
    guards against anyone re-introducing the strip-only form."""
    body = _wrapper()
    # The exact strip-only form from PR #126 must NOT be in the wrapper.
    assert "sed 's/^#//'" not in body, (
        "strip-only form ('/^#//') leaves master/query flush left — "
        "Sybase parses them as server names, re-triggering the "
        "ct_connect failure.  Use '#' → TAB (via $TAB from printf) "
        "instead.")


def test_wrapper_passes_minus_I_to_isql_when_tmp_written():
    """isql invocation must consult the sed-stripped tmp interfaces
    via `-I`.  Without this, isql still reads the on-target original
    (with its '#'-commented endpoints) and the fix is a no-op."""
    body = _wrapper()
    # The -I arg is built conditionally so the fix stays harmless when
    # /sybase/<SID>/interfaces is missing entirely.
    assert "IFACE_ARG=\"-I$IFACE_TMP\"" in body, (
        "when the sed-strip succeeds, IFACE_ARG must point isql at "
        "the tmp copy via -I")
    assert "$IFACE_ARG" in body, (
        "isql command line must splice $IFACE_ARG so the -I lookup "
        "actually fires when the tmp was written")
    # The isql line itself still carries -S $SID so the server-name
    # header lookup still works (strip '#' only exposes endpoints,
    # doesn't change server names).
    assert re.search(
        r'"\$ISQL" -U"\$DBUSER" -P"\$PW" -S"\$SID"\s+\$IFACE_ARG\s+-X',
        body), (
        "isql invocation must retain -S $SID AND splice $IFACE_ARG "
        "before -X / -w / -i")


def test_wrapper_lenient_parse_is_safe_when_interfaces_missing():
    """If /sybase/<SID>/interfaces doesn't exist (unusual install
    layout), the lenient parse must not crash the wrapper — isql
    then runs with no -I and the pre-fix behaviour (lookup against
    $SYBASE/interfaces via isql's own default) stays in effect."""
    body = _wrapper()
    # The sed+tmp write is guarded by `[ -f "$IFACE_SRC" ]`.
    assert "if [ -f \"$IFACE_SRC\" ]; then" in body, (
        "lenient parse must only fire when the source interfaces "
        "exists")
    # IFACE_ARG default is empty, so the isql line falls through
    # cleanly on a missing interfaces file.
    assert "IFACE_ARG=\"\"" in body, (
        "IFACE_ARG must default to empty string so an isql call "
        "without -I is produced on missing-interfaces installs")


def test_wrapper_lenient_parse_is_safe_when_sed_fails():
    """sed may fail (read-only /tmp, exotic SELinux policy, etc).
    The wrapper must swallow the failure and continue with the
    pre-fix behaviour instead of EXIT=1."""
    body = _wrapper()
    # The sed invocation redirects stderr to /dev/null AND is wrapped
    # in `if sed ...; then IFACE_ARG=...` so a non-zero exit skips
    # the -I arg setup.
    assert (
        "sed \"s/^#/$TAB/\" \"$IFACE_SRC\" > \"$IFACE_TMP\" 2>/dev/null"
        in body
    ), "sed stderr must be swallowed so permission errors don't abort"
    assert "if sed" in body, (
        "sed call must be in a conditional so a non-zero exit "
        "(permission denied, etc) doesn't abort the whole wrapper")


# ---------------------------------------------------------------------------
# Preserved pre-fix behaviour (regression guard)
# ---------------------------------------------------------------------------

def test_wrapper_still_passes_minus_S_sid_and_minus_X():
    """The server-name lookup and encrypted-login flags stay in
    place — the fix only ADDS the -I tmpfile arg, doesn't remove the
    pre-existing isql options."""
    body = _wrapper(sid="SM1")
    assert "SID=\"SM1\"" in body
    assert "-X" in body, (
        "-X (encrypted password login) must stay — SAP-on-Sybase "
        "requires it per the comment block")
    assert "-w200" in body, (
        "-w200 (wide output) must stay for readable isql output")


def test_wrapper_still_locates_isql_under_sybase_ocs():
    """Wrapper's isql locator (glob /sybase/*/OCS-*/bin/isql) must
    stay — the lenient-interfaces fix is upstream of it in the
    control flow."""
    body = _wrapper()
    assert "for d in /sybase/*/OCS-*/bin/isql; do" in body


def test_wrapper_still_sets_ld_library_path():
    """LD_LIBRARY_PATH setup (OCS-*/lib + lib3p + lib3p64) must
    stay — needed by -X (libsybcsi_core)."""
    body = _wrapper()
    assert "export LD_LIBRARY_PATH" in body
    assert "lib3p64" in body


def test_wrapper_uses_fixed_sqlfile_path_not_dollar_one():
    """Pre-fix bug fix (hard-coded SQL file path instead of $1)
    must stay — SAPXPG duplicates argv and $1 would read the
    wrapper itself as SQL input."""
    body = _wrapper()
    assert "SQLFILE=\"/tmp/sapmap_gw_syb.sql\"" in body, (
        "SQLFILE path must be the hard-coded constant, not $1 — "
        "SAPXPG argv-duplicate bug would otherwise fire the "
        "wrapper against itself")


def test_wrapper_sed_recipe_against_operator_lab_sm1_sample():
    """End-to-end check: extract the sed invocation from the wrapper
    body, run it under /bin/sh against the exact interfaces file
    content the operator pasted from live lab SM1 (2026-10-09), and
    assert the output is a valid Sybase interfaces file — i.e.
    endpoint lines (master, query) are TAB-indented so Sybase treats
    them as endpoints under their parent server header.

    This is the regression test that would have CAUGHT PR #126 if we
    had written it then: a strip-only sed produces a file where
    `master tcp ether srv01sm1 4901` is flush at col 0, which Sybase
    parses as a new server-name header.
    """
    import os
    import shutil
    import subprocess
    import tempfile

    _w = _import_writers_safely()
    body = _w._build_sybase_wrapper_script("SM1")

    # Operator's live SM1 interfaces (pasted 2026-10-09)
    source = (
        "SM1\n"
        "#master tcp ether srv01sm1 4901\n"
        "#query  tcp ether srv01sm1 4901\n"
        "\n"
        "SM1_BS\n"
        "#master tcp ether srv01sm1 4902\n"
        "#query  tcp ether srv01sm1 4902\n"
        "\n"
        "SM1_JSAGENT\n"
        "#master tcp ether srv01sm1 4903\n"
        "#query  tcp ether srv01sm1 4903\n"
    )

    tmpdir = tempfile.mkdtemp(prefix="sapmap_syb_test_")
    try:
        src_path = os.path.join(tmpdir, "interfaces")
        dst_path = os.path.join(tmpdir, "iface_tmp.cfg")
        with open(src_path, "w") as fh:
            fh.write(source)

        # Pull the exact sed line out of the wrapper so a future
        # refactor of the sed recipe stays covered.
        m = re.search(
            r'sed "s/\^#/\$TAB/" "\$IFACE_SRC" > "\$IFACE_TMP" 2>/dev/null',
            body,
        )
        assert m, (
            "could not find the wrapper's sed recipe — if the shape "
            "changed, update this test together with the wrapper")

        # Reproduce the wrapper's TAB resolution + sed call exactly.
        shell_recipe = (
            f'TAB="$(printf \'\\t\')"\n'
            f'IFACE_SRC="{src_path}"\n'
            f'IFACE_TMP="{dst_path}"\n'
            f'sed "s/^#/$TAB/" "$IFACE_SRC" > "$IFACE_TMP"\n'
        )
        rc = subprocess.run(
            ["/bin/sh", "-c", shell_recipe],
            capture_output=True,
            text=True,
        )
        assert rc.returncode == 0, (
            f"wrapper's sed recipe failed under /bin/sh: "
            f"stderr={rc.stderr!r}")

        with open(dst_path) as fh:
            rewritten = fh.read()

        # Three server-name headers survive (flush at col 0) + their
        # endpoint lines must each start with a TAB.
        headers = [line for line in rewritten.splitlines()
                   if line and not line[0].isspace()]
        assert headers == ["SM1", "SM1_BS", "SM1_JSAGENT"], (
            f"expected exactly 3 server-name headers flush at col 0 "
            f"after rewrite; got {headers!r} — a stripped '#' with no "
            f"replacement TAB would list `master tcp ether srv01sm1 "
            f"4901` here, breaking the Sybase parse.")

        # Endpoint lines must be TAB-indented so Sybase recognises them.
        endpoint_lines = [
            line for line in rewritten.splitlines()
            if line.startswith("\t")
        ]
        assert len(endpoint_lines) == 6, (
            f"expected 6 TAB-indented endpoint lines (3 server x "
            f"master+query); got {len(endpoint_lines)}: "
            f"{endpoint_lines!r}")
        assert all(
            l.lstrip("\t").startswith(("master", "query"))
            for l in endpoint_lines), (
            f"TAB-indented lines must be master/query entries; "
            f"got {endpoint_lines!r}")
        # Specifically the SM1 host:port must survive intact.
        assert "\tmaster tcp ether srv01sm1 4901" in rewritten, (
            "SM1 master endpoint must be preserved verbatim after "
            "the # → TAB rewrite")
        assert "\tquery  tcp ether srv01sm1 4901" in rewritten, (
            "SM1 query endpoint must be preserved verbatim after "
            "the # → TAB rewrite")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_module_constants_do_not_collide():
    """The four on-target /tmp paths (wrapper, SQL, out, iface)
    must stay distinct — a collision would corrupt output."""
    _w = _import_writers_safely()
    paths = {
        _w._SYBASE_WRAPPER_PATH,
        _w._SYBASE_SQL_PATH,
        _w._SYBASE_OUT_PATH,
        _w._SYBASE_IFACE_PATH,
    }
    assert len(paths) == 4, (
        f"on-target /tmp paths must be distinct; got "
        f"collision in {paths!r}")
