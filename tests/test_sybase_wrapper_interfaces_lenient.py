#!/usr/bin/env python3
"""Regression tests for the Sybase wrapper's server-name resolution
(operator lab SM1 report 2026-10-09 + SAP Note 2502094).

Symptom: GW SAPXPG + sybase writer confirmed OS-exec (whoami=sm1adm)
but every SQL insert group failed with:

    CT-LIBRARY error:
    ct_connect(): directory service layer: internal directory control
    layer error: Requested server name not found.
    SAPMAP:EXIT=255

Two scenarios (both live-observed) produce the identical message:

  1. Admin-disabled endpoints — operator lab SM1.
     /sybase/SM1/interfaces had the master/query lines prefixed with
     '#'.  isql -S SM1 found the SM1 header but no usable endpoint.

  2. Corrupted interfaces — SAP Note 2502094.
     /sybase/SID/interfaces LOOKS fine to `cat` and `vim` but carries
     hidden control chars (CR, NUL, VT, FF, SO).  `file interfaces`
     reports 'CORRUPTED' and the SAP Note's recommended workaround is
     to bypass the interfaces file entirely via isql's `-S host:port`
     direct-connect syntax.

Fix.  Two-tier resolution inside the wrapper:

  PRIMARY: extract host:port from the on-target interfaces using
  `tr -d <hidden-chars> | sed <strip-#> | awk <pick-master>`.
  Pass `-S host:port` to isql — bypasses CT-LIB directory lookup
  entirely, rescues both scenarios above.

  FALLBACK: if host:port extraction returned nothing (empty / missing
  interfaces, or a format awk couldn't parse), fall back to rewriting
  the interfaces file to a session-tmp copy via `sed "s/^#/<TAB>/"`
  and point isql at it via `-I`.  '#' → TAB (not strip) because
  Sybase's directory parser treats col-0 lines as new server-name
  headers.

Diagnostic marker.  The wrapper writes `SAPMAP:iface=<path>` to the
output file so the caller can see which resolution path fired —
'direct-connect host:port=…' / 'sed-rewrite -I…' / 'on-disk-
interfaces -S…'.  Invaluable when debugging a connect failure.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

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
# PRIMARY path — host:port extraction + -S host:port direct-connect
# ---------------------------------------------------------------------------

def test_wrapper_extracts_hostport_from_interfaces():
    """Wrapper must build HOSTPORT by piping interfaces through
    tr -d (hidden chars) | sed (strip #) | awk (pick master line
    and print host:port)."""
    body = _wrapper()
    # tr call must strip the hidden-char set the SAP Note calls out:
    # CR (\\r), NUL (\\000), SO (\\017), VT (\\013), FF (\\014).
    assert "tr -d '\\r\\000\\017\\013\\014'" in body, (
        "tr call must strip CR/NUL/SO/VT/FF — the hidden-char set "
        "SAP Note 2502094 reports as the cause of 'CORRUPTED' "
        "interfaces files")
    # sed call must strip optional leading '#' + whitespace so a
    # commented-out endpoint re-enters the pipeline normalized.
    assert "sed 's/^[[:space:]]*#\\{0,1\\}[[:space:]]*//'" in body, (
        "sed call must strip leading '#' and surrounding whitespace "
        "so #master and bare master lines both normalize")
    # awk must match 'master tcp ether <host> <port>' and output
    # $4 ":" $5 — the first match wins (exit).
    assert ("awk '/^master[[:space:]]+tcp[[:space:]]+ether[[:space:]]+/"
            " { print $4 \":\" $5; exit }'") in body, (
        "awk must pick the FIRST master-tcp-ether line and print "
        "host:port — first match wins (exit)")


def test_wrapper_prefers_hostport_direct_connect_over_sid_lookup():
    """When HOSTPORT is non-empty, isql must receive -S host:port
    (direct-connect, bypasses CT-LIB interfaces lookup entirely).
    This is the primary SAP Note 2502094 rescue path."""
    body = _wrapper()
    assert "if [ -n \"$HOSTPORT\" ]; then" in body, (
        "wrapper must branch on HOSTPORT — primary path when "
        "extraction succeeded")
    assert "SERVER_ARG=\"-S$HOSTPORT\"" in body, (
        "when HOSTPORT is set, SERVER_ARG must be -S$HOSTPORT so "
        "isql uses direct-connect")


def test_wrapper_sets_sid_fallback_when_no_hostport():
    """SERVER_ARG default must be -S$SID so the fallback /
    last-resort paths still produce a usable isql command."""
    body = _wrapper(sid="SM1")
    assert "SERVER_ARG=\"-S$SID\"" in body, (
        "SERVER_ARG default must be -S$SID so the last-resort path "
        "(no HOSTPORT, no sed-rewrite) still has a server-name arg")


def test_wrapper_isql_invocation_uses_server_arg_variable():
    """isql command line must splice $SERVER_ARG (expands to either
    -S host:port or -S $SID) instead of hard-coding -S $SID."""
    body = _wrapper()
    # The invocation must use $SERVER_ARG unquoted (so host:port
    # expands as a single arg including the -S prefix).
    assert re.search(
        r'"\$ISQL" -U"\$DBUSER" -P"\$PW"\s+\$SERVER_ARG\s+\$IFACE_ARG\s+-X',
        body), (
        "isql invocation must splice $SERVER_ARG before $IFACE_ARG — "
        "primary direct-connect vs fallback -I$iface_tmp both reach "
        "isql through this one line")
    # Pre-fix hard-coded -S$SID (plus the two quote variants) must
    # NOT appear in the invocation line any more.
    inv_line = next(
        l for l in body.splitlines()
        if "\"$ISQL\"" in l and "-U\"$DBUSER\"" in l)
    assert "-S\"$SID\"" not in inv_line, (
        "isql invocation line must no longer hard-code -S\"$SID\" — "
        "PR #126/#127 regression; use $SERVER_ARG instead")


# ---------------------------------------------------------------------------
# FALLBACK path — sed-rewrite (-I iface_tmp) when HOSTPORT extraction fails
# ---------------------------------------------------------------------------

def test_wrapper_declares_iface_tmp_path():
    """Session-tmp interfaces copy lives under /tmp with a stable name
    so repeat invocations don't accumulate garbage."""
    _w = _import_writers_safely()
    assert hasattr(_w, "_SYBASE_IFACE_PATH"), (
        "wrapper must export the tmp-interfaces path as a module "
        "constant so callers / tests can clean it up predictably")
    assert _w._SYBASE_IFACE_PATH.startswith("/tmp/"), (
        f"iface tmp path must land under /tmp; got "
        f"{_w._SYBASE_IFACE_PATH!r}")


def test_wrapper_sed_rewrite_fallback_fires_when_no_hostport():
    """When HOSTPORT extraction returns nothing (unparseable file),
    fall back to rewriting interfaces with # → TAB and pointing isql
    at it via -I.  PR #127's approach as a safety net."""
    body = _wrapper()
    # The fallback branch is explicitly `elif [ -f "$IFACE_SRC" ]`.
    assert "elif [ -f \"$IFACE_SRC\" ]; then" in body, (
        "fallback must branch on `-n HOSTPORT` first, then "
        "`-f IFACE_SRC` — sed-rewrite only when HOSTPORT didn't "
        "come through")
    # TAB resolution + sed call still present (PR #127 fix).
    assert "TAB=\"$(printf '\\t')\"" in body, (
        "TAB resolution via printf must stay — dash/busybox don't "
        "honour `sed 's/.../\\t/'`")
    assert "sed \"s/^#/$TAB/\" \"$IFACE_SRC\" > \"$IFACE_TMP\"" in body, (
        "sed-rewrite call must replace '#' with TAB (not strip!) — "
        "preserves standard Sybase indent for endpoint lines")
    # -I is set only when sed-rewrite succeeds.
    assert "IFACE_ARG=\"-I$IFACE_TMP\"" in body


def test_wrapper_sed_does_not_strip_hash_without_tab():
    """Regression pin from PR #127.  PR #126 shipped `sed 's/^#//'`
    which left master/query flush at col 0.  Sybase treated them as
    new server-name headers and ct_connect still errored.  Guard
    against anyone re-introducing the strip-only form."""
    body = _wrapper()
    assert "sed 's/^#//'" not in body, (
        "strip-only form must not reappear — leaves master/query "
        "flush left, Sybase parses them as server names")


def test_wrapper_hostport_extraction_safe_when_interfaces_missing():
    """If /sybase/<SID>/interfaces doesn't exist, both HOSTPORT
    extraction and sed-rewrite must skip cleanly — SERVER_ARG stays
    at the default -S$SID and the wrapper runs isql with no -I."""
    body = _wrapper()
    # Both branches gated on `[ -f "$IFACE_SRC" ]`.
    assert "if [ -f \"$IFACE_SRC\" ]; then" in body
    # HOSTPORT must default to empty string.
    assert "HOSTPORT=\"\"" in body, (
        "HOSTPORT must default to empty so the primary branch "
        "doesn't trigger on missing interfaces")
    # IFACE_ARG must default to empty so isql runs without -I in
    # the last-resort path.
    assert "IFACE_ARG=\"\"" in body, (
        "IFACE_ARG must default to empty for the no-interfaces "
        "last-resort path")


def test_wrapper_sed_fallback_swallows_sed_failure():
    """sed may fail (read-only /tmp, SELinux policy).  Wrapper must
    swallow it (2>/dev/null + `if sed ...; then ...`) and continue
    without -I rather than EXIT=1."""
    body = _wrapper()
    assert (
        "if sed \"s/^#/$TAB/\" \"$IFACE_SRC\" > \"$IFACE_TMP\" "
        "2>/dev/null; then"
    ) in body, (
        "sed-rewrite call must be in a conditional so a non-zero "
        "exit doesn't abort the whole wrapper")


# ---------------------------------------------------------------------------
# Diagnostic marker — operator can see which path the wrapper took
# ---------------------------------------------------------------------------

def test_wrapper_writes_diagnostic_marker_for_each_resolution_path():
    """Wrapper must echo SAPMAP:iface=<path> to $OUT before isql
    runs so the caller / operator can tell which resolution path
    was tried when debugging a connect failure.  Three paths, three
    distinct markers."""
    body = _wrapper()
    assert "echo \"SAPMAP:iface=direct-connect host:port=$HOSTPORT\"" in body, (
        "primary path must emit 'direct-connect' diagnostic")
    assert "echo \"SAPMAP:iface=sed-rewrite -I$IFACE_TMP\"" in body, (
        "fallback path must emit 'sed-rewrite' diagnostic")
    assert "echo \"SAPMAP:iface=on-disk-interfaces -S$SID\"" in body, (
        "last-resort path must emit 'on-disk-interfaces' diagnostic")


# ---------------------------------------------------------------------------
# Preserved pre-fix behaviour (regression guard)
# ---------------------------------------------------------------------------

def test_wrapper_still_passes_minus_X_and_minus_w200():
    """The encrypted-login + wide-output flags stay in place — the
    server-name fix only CHANGES the -S arg, doesn't remove other
    pre-existing isql options."""
    body = _wrapper(sid="SM1")
    assert "SID=\"SM1\"" in body
    assert "-X" in body, (
        "-X (encrypted password login) must stay — SAP-on-Sybase "
        "requires it")
    assert "-w200" in body, (
        "-w200 (wide output) must stay for readable isql output")


def test_wrapper_locator_prefers_sid_specific_sybase_install():
    """On multi-SID hosts (shared /sybase/ root with /sybase/DEV +
    /sybase/SM1 both installed — common on consolidated labs + dual-
    stack systems), the plain /sybase/* glob expands alphabetically.
    DEV wins, SYBASE/IFACE_SRC point at the wrong install, HOSTPORT
    extracts DEV's master line, and isql connects to the DEV Sybase.
    `use SM1` in the SQL batch either errors cleanly (operator sees
    it) OR silently cross-connects if DEV has a database literally
    named SM1 (SAP CPS / dual-stack installs do this), landing
    SAPMAP00 in the WRONG landscape.

    Pre-SAP-Note-2502094 code (PR #126/#127) masked this because
    `-S $SID` with DEV's interfaces errored 'Requested server name
    not found' and surfaced the mis-targeting.  The direct-connect
    fix (this PR) removes that safety net, so the locator MUST
    prefer the SID-specific install first.

    Caught by adversarial review workflow 2026-10-09 (two independent
    lenses — security-and-injection + fallback-chain-correctness —
    both flagged this as CRITICAL/HIGH silent-data-corruption)."""
    body = _wrapper(sid="SM1")
    # SID-specific glob must come FIRST in the loop so a /sybase/SM1/
    # install wins over any /sybase/DEV/ sibling.
    assert "for d in /sybase/\"$SID\"/OCS-*/bin/isql /sybase/*/OCS-*/bin/isql; do" in body, (
        "isql locator must try /sybase/$SID/ FIRST (prevents multi-SID "
        "silent mis-targeting), then fall back to the wildcard glob")


def test_wrapper_still_locates_isql_under_sybase_ocs():
    """Wrapper's isql locator still globs /sybase/*/OCS-*/bin/isql as
    the fallback — the SID-first fix only PREPENDS a more-specific
    pattern, doesn't remove the wildcard safety net (which rescues
    installs where /sybase/<SID>/ isn't the real path).  The server-
    name fix is downstream of the locator."""
    body = _wrapper()
    assert "/sybase/*/OCS-*/bin/isql" in body


def test_wrapper_sid_first_locator_rescues_dev_sm1_colocation():
    """End-to-end: a /bin/sh invocation of the actual locator loop
    against a filesystem shaped like a real multi-SID host (DEV +
    SM1 isql binaries both present) must pick SM1 when SID=SM1."""
    _w = _import_writers_safely()
    body = _w._build_sybase_wrapper_script("SM1")
    # Extract the locator loop line.
    m = re.search(
        r'for d in (/sybase/[^;]+/bin/isql[^;]*); do',
        body)
    assert m, "could not find the isql locator loop in wrapper body"
    glob_pattern = m.group(1).strip()

    tmpdir = tempfile.mkdtemp(prefix="sapmap_syb_multisid_")
    try:
        # Build a filesystem shaped like a real multi-SID install:
        # both /sybase/DEV/OCS-16_0/bin/isql and
        # /sybase/SM1/OCS-16_0/bin/isql present + executable.
        # Rooted at tmpdir to avoid touching /sybase/.
        for sid in ("DEV", "SM1"):
            isql_dir = os.path.join(tmpdir, "sybase", sid, "OCS-16_0", "bin")
            os.makedirs(isql_dir)
            isql_path = os.path.join(isql_dir, "isql")
            with open(isql_path, "w") as fh:
                fh.write("#!/bin/sh\necho stub\n")
            os.chmod(isql_path, 0o755)

        # Reroot the glob pattern under tmpdir for the test.
        rerooted_glob = glob_pattern.replace(
            "/sybase/", f"{tmpdir}/sybase/")

        shell_cmd = (
            f'SID="SM1"\n'
            f'ISQL=""\n'
            f'for d in {rerooted_glob}; do\n'
            f'  [ -x "$d" ] && ISQL="$d" && break\n'
            f'done\n'
            f'echo "$ISQL"\n'
        )
        rc = subprocess.run(
            ["/bin/sh", "-c", shell_cmd],
            capture_output=True, text=True)
        assert rc.returncode == 0, (
            f"locator loop failed under /bin/sh: {rc.stderr!r}")
        picked = rc.stdout.strip()
        assert "/sybase/SM1/" in picked, (
            f"locator must pick /sybase/SM1/ when SID=SM1 on a multi-SID "
            f"host; got {picked!r}.  Pre-fix bug: alphabetical glob picks "
            f"/sybase/DEV/ and SAPMAP00 lands in the wrong landscape.")
        assert "/sybase/DEV/" not in picked, (
            f"locator must NOT pick /sybase/DEV/ when SID=SM1; got "
            f"{picked!r}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_wrapper_locator_falls_back_to_wildcard_when_sid_not_installed():
    """If /sybase/<SID>/ doesn't exist (unusual install where the
    Sybase root uses a non-SID name, e.g. /sybase/sapdb/), the
    wildcard fallback must still work.  Guards against the SID-first
    fix accidentally breaking existing single-SID / non-SID-named
    installs."""
    _w = _import_writers_safely()
    body = _w._build_sybase_wrapper_script("SM1")
    m = re.search(
        r'for d in (/sybase/[^;]+/bin/isql[^;]*); do',
        body)
    assert m
    glob_pattern = m.group(1).strip()

    tmpdir = tempfile.mkdtemp(prefix="sapmap_syb_fallback_")
    try:
        # Only /sybase/sapdb/... exists; no /sybase/SM1/.
        isql_dir = os.path.join(tmpdir, "sybase", "sapdb", "OCS-16_0", "bin")
        os.makedirs(isql_dir)
        isql_path = os.path.join(isql_dir, "isql")
        with open(isql_path, "w") as fh:
            fh.write("#!/bin/sh\necho stub\n")
        os.chmod(isql_path, 0o755)

        rerooted_glob = glob_pattern.replace(
            "/sybase/", f"{tmpdir}/sybase/")
        shell_cmd = (
            f'SID="SM1"\n'
            f'ISQL=""\n'
            f'for d in {rerooted_glob}; do\n'
            f'  [ -x "$d" ] && ISQL="$d" && break\n'
            f'done\n'
            f'echo "$ISQL"\n'
        )
        rc = subprocess.run(
            ["/bin/sh", "-c", shell_cmd],
            capture_output=True, text=True)
        assert rc.returncode == 0
        picked = rc.stdout.strip()
        assert "/sybase/sapdb/" in picked, (
            f"wildcard fallback must find /sybase/sapdb/ when /sybase/"
            f"$SID/ doesn't exist; got {picked!r}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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
    assert "SQLFILE=\"/tmp/sapmap_gw_syb.sql\"" in body


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
        f"on-target /tmp paths must be distinct; got {paths!r}")


# ---------------------------------------------------------------------------
# End-to-end simulation — run the wrapper's pipeline against lab-shaped data
# ---------------------------------------------------------------------------

def _extract_shell_pipeline(wrapper_body: str) -> str:
    """Pull the EXACT tr | sed | awk pipeline out of the wrapper
    body so the end-to-end tests exercise what actually ships.
    Returns the pipeline as a single-line shell fragment ending with
    the awk closing quote.
    """
    m = re.search(
        r"HOSTPORT=\$\((.*?)\)\n",
        wrapper_body, re.DOTALL)
    assert m, "could not find HOSTPORT=$(...) in wrapper body"
    # Strip embedded backslash-newlines so the whole pipeline runs
    # on one line via /bin/sh -c.
    return re.sub(r"\\\n\s*", " ", m.group(1))


def _run_hostport_pipeline(interfaces_content: str) -> str:
    """Write interfaces_content to a tmp file, run the wrapper's
    exact tr | sed | awk pipeline against it under /bin/sh, return
    the HOSTPORT string (stripped)."""
    _w = _import_writers_safely()
    body = _w._build_sybase_wrapper_script("SM1")
    pipeline = _extract_shell_pipeline(body)

    tmpdir = tempfile.mkdtemp(prefix="sapmap_syb_iface_test_")
    try:
        src_path = os.path.join(tmpdir, "interfaces")
        with open(src_path, "wb") as fh:
            fh.write(interfaces_content.encode("latin-1"))
        # Substitute $IFACE_SRC in the pipeline for the real path.
        shell_cmd = f"IFACE_SRC='{src_path}'; " + pipeline
        rc = subprocess.run(
            ["/bin/sh", "-c", f"echo \"$({shell_cmd})\""],
            capture_output=True, text=True)
        assert rc.returncode == 0, (
            f"wrapper pipeline failed under /bin/sh: {rc.stderr!r}")
        return rc.stdout.strip()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_pipeline_extracts_hostport_from_operator_lab_sm1_commented():
    """Operator lab SM1 (2026-10-09): endpoint lines prefixed with
    '#'.  Pipeline must extract srv01sm1:4901 from the first (SM1)
    header's #master line, ignoring SM1_BS / SM1_JSAGENT."""
    content = (
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
    assert _run_hostport_pipeline(content) == "srv01sm1:4901", (
        "operator lab SM1 (commented endpoints) must extract "
        "srv01sm1:4901 — the first master line")


def test_pipeline_extracts_hostport_from_sap_note_2502094_sample():
    """SAP Note 2502094 KBA sample (uncommented, standard format).
    Pipeline must extract falsapnwg01:4901."""
    content = (
        "SID\n"
        "\tmaster tcp ether falsapnwg01 4901\n"
        "\tquery tcp ether falsapnwg01 4901\n"
        "\n"
        "SID_BS\n"
        "\tmaster tcp ether falsapnwg01 4902\n"
        "\tquery tcp ether falsapnwg01 4902\n"
    )
    assert _run_hostport_pipeline(content) == "falsapnwg01:4901", (
        "SAP Note 2502094 sample (standard-indent) must extract "
        "falsapnwg01:4901 — the first master line")


def test_pipeline_tolerates_hidden_chars_in_corrupted_interfaces():
    """SAP Note 2502094 cause: hidden control chars (CR, NUL, VT,
    FF, SO) that `cat` renders invisibly but CT-LIB rejects as
    'CORRUPTED'.  Our tr -d strips them all; awk still finds the
    master line and emits host:port."""
    # Inject each hidden char at various positions in the file.
    content = (
        "SM1\r\n"
        "\tmaster\0 tcp\017 ether\013 srv01sm1\014 4901\r\n"
        "\tquery tcp ether srv01sm1 4901\n"
    )
    # tr strips the hidden chars → the master line normalises to
    # `master tcp ether srv01sm1 4901` which awk matches cleanly.
    assert _run_hostport_pipeline(content) == "srv01sm1:4901", (
        "hidden control chars must be stripped by tr so the awk "
        "pattern matches and emits srv01sm1:4901")


def test_pipeline_handles_mixed_commented_and_bare_endpoints():
    """Mixed-format interfaces: some endpoints commented out, others
    bare.  Pipeline must still extract from the first master line it
    sees, regardless of comment state."""
    content = (
        "SM1\n"
        "\tmaster tcp ether srv01sm1 4901\n"
        "#query  tcp ether srv01sm1 4901\n"
    )
    assert _run_hostport_pipeline(content) == "srv01sm1:4901"


def test_pipeline_empty_interfaces_yields_empty_hostport():
    """Empty interfaces → pipeline produces no match → HOSTPORT
    stays empty.  Wrapper then falls back to -S$SID + sed-rewrite."""
    assert _run_hostport_pipeline("") == ""


def test_pipeline_only_server_headers_no_master_yields_empty():
    """Interfaces with headers but no master lines (truly broken
    install) → HOSTPORT empty → fallback kicks in."""
    content = (
        "SM1\n"
        "SM1_BS\n"
        "SM1_JSAGENT\n"
    )
    assert _run_hostport_pipeline(content) == ""


def test_pipeline_tolerates_extra_whitespace_between_fields():
    """Admin-touched interfaces might have multiple spaces or tabs
    between master/tcp/ether/host/port — awk's [[:space:]]+ handles
    any whitespace run."""
    content = (
        "SM1\n"
        "\tmaster\t\ttcp \t ether   srv01sm1 \t  4901\n"
    )
    assert _run_hostport_pipeline(content) == "srv01sm1:4901"


# ---------------------------------------------------------------------------
# Sed-fallback end-to-end — unchanged from PR #127, keeps the covenant
# ---------------------------------------------------------------------------

def test_sed_rewrite_against_operator_lab_sm1_sample():
    """End-to-end check for the FALLBACK path (sed-rewrite + -I):
    extract the sed invocation from the wrapper, run it under /bin/sh
    against the operator-pasted SM1 interfaces content, and assert
    the output is a valid Sybase interfaces file (3 server headers
    flush at col 0, 6 TAB-indented endpoints).

    This fallback only fires when HOSTPORT extraction fails — but
    the sed-rewrite must still produce a Sybase-parseable file in
    that case, so this covenant stays.
    """
    _w = _import_writers_safely()
    body = _w._build_sybase_wrapper_script("SM1")

    source = (
        "SM1\n"
        "#master tcp ether srv01sm1 4901\n"
        "#query  tcp ether srv01sm1 4901\n"
        "\n"
        "SM1_BS\n"
        "#master tcp ether srv01sm1 4902\n"
        "#query  tcp ether srv01sm1 4902\n"
    )

    tmpdir = tempfile.mkdtemp(prefix="sapmap_syb_test_")
    try:
        src_path = os.path.join(tmpdir, "interfaces")
        dst_path = os.path.join(tmpdir, "iface_tmp.cfg")
        with open(src_path, "w") as fh:
            fh.write(source)

        # Pull the exact sed line out of the wrapper so a refactor of
        # the sed recipe stays covered.
        assert re.search(
            r'sed "s/\^#/\$TAB/" "\$IFACE_SRC" > "\$IFACE_TMP" 2>/dev/null',
            body
        ), "could not find the wrapper's sed-rewrite recipe"

        shell_recipe = (
            f'TAB="$(printf \'\\t\')"\n'
            f'IFACE_SRC="{src_path}"\n'
            f'IFACE_TMP="{dst_path}"\n'
            f'sed "s/^#/$TAB/" "$IFACE_SRC" > "$IFACE_TMP"\n'
        )
        rc = subprocess.run(
            ["/bin/sh", "-c", shell_recipe],
            capture_output=True, text=True)
        assert rc.returncode == 0, (
            f"wrapper's sed recipe failed under /bin/sh: {rc.stderr!r}")

        with open(dst_path) as fh:
            rewritten = fh.read()

        headers = [line for line in rewritten.splitlines()
                   if line and not line[0].isspace()]
        assert headers == ["SM1", "SM1_BS"], (
            f"expected 2 server-name headers flush at col 0 after "
            f"rewrite; got {headers!r}")

        endpoint_lines = [
            line for line in rewritten.splitlines()
            if line.startswith("\t")
        ]
        assert len(endpoint_lines) == 4, (
            f"expected 4 TAB-indented endpoint lines; got "
            f"{len(endpoint_lines)}: {endpoint_lines!r}")
        assert "\tmaster tcp ether srv01sm1 4901" in rewritten
        assert "\tquery  tcp ether srv01sm1 4901" in rewritten
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
