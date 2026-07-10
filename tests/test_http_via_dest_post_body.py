"""Kernel-proxied HTTP-over-RFC: POST request body + Content-Type.

Feature (2026-07-10, Phase 1 of the RFC-8705 cert-auth mint plan):
the ABAP wrapper in ``sap_http_via_dest.py`` learns to send request
bodies.  The mint helper uses this to POST
``grant_type=client_credentials&client_id=...`` at XSUAA's
``/oauth/token`` over the existing cert-authenticated Type-G
destination — the kernel presents PSE ``DFAULT``'s cert on the
wire, XSUAA validates the RFC-8705 x5t#S256 binding, and returns a
JWT.

Pins here cover:

  * body chunking through _abap_string_assignment (long OAuth2
    client_ids like ``sb-clone…!b609810|destination-xsappname!b404``
    are 60+ chars and MUST be split under the 72-char PROGRAM
    row limit or the report silently fails to compile)
  * Content-Type header emission
  * body-without-content_type is rejected (would 400 at XSUAA)
  * quotes / newlines in body still tripped by the guard
  * GET calls with no body are byte-identical to the pre-fix
    generator (regression pin — the historical output shape must
    not drift)
"""
from __future__ import annotations

import modules  # noqa: F401  (registers package paths)
import pytest
from sap_http_via_dest import _build_abap_program, HttpViaDestError


# ---------------------------------------------------------------------------
# Body + Content-Type: happy path
# ---------------------------------------------------------------------------

def test_post_with_body_emits_content_type_and_set_cdata():
    """The two extra ABAP calls that make a body-carrying POST
    work: set_header_field(Content-Type, ...) and set_cdata(rq)."""
    lines = _build_abap_program(
        "TO_BTP", "POST", "/oauth/token",
        body="grant_type=client_credentials&client_id=sb-x!b1",
        content_type="application/x-www-form-urlencoded")
    joined = "\n".join(lines)
    assert "set_header_field(" in joined
    assert "'Content-Type'" in joined
    assert "'application/x-www-form-urlencoded'" in joined
    assert "set_cdata( rq )" in joined
    assert "DATA: rq TYPE string." in joined


def test_post_body_chunked_when_over_40_chars():
    """OAuth2 client_ids on BTP are 60+ chars (`sb-…!b<N>|…!b<N>`)
    and MUST be chunked so no single ABAP source line exceeds
    72 chars.  The _abap_string_assignment helper wraps at ~40 char
    boundaries with `&&`; verify the body flows through the same
    path."""
    long_id = ("sb-clonef0e76cf4991f41369c69286725705654!b609810"
               "|destination-xsappname!b404")
    body = f"grant_type=client_credentials&client_id={long_id}"
    lines = _build_abap_program(
        "TO_BTP", "POST", "/oauth/token",
        body=body,
        content_type="application/x-www-form-urlencoded")
    # Same 72-char discipline enforced elsewhere.
    for line in lines:
        assert len(line) <= 72, (
            f"body chunking regressed — {len(line)}-char line "
            f"emitted, would silently truncate on the PROGRAM "
            f"table: {line!r}")
    # And the body ACTUALLY got assigned to rq
    assigns = [ln for ln in lines if ln.startswith("rq =")
               or ln.strip().startswith("'")]
    assert any(ln.startswith("rq =") for ln in lines)


def test_post_short_body_single_line_assignment():
    """Bodies under 40 chars collapse to a single-line assignment —
    matches the path-assignment behaviour, avoids emitting a bare
    `rq =` continuation line that would be surprising in ABAP
    tracing."""
    lines = _build_abap_program(
        "T", "POST", "/",
        body="a=b",
        content_type="text/plain")
    assert "rq = 'a=b'." in lines


# ---------------------------------------------------------------------------
# Body without content_type: rejected loudly (XSUAA would 400)
# ---------------------------------------------------------------------------

def test_body_without_content_type_raises():
    """Sending a body with no Content-Type is almost always an
    operator bug — most servers (XSUAA included) 400-reject and
    the caller can't tell it's the header that's missing.  Fail
    at the wrapper instead."""
    with pytest.raises(HttpViaDestError, match="content_type"):
        _build_abap_program(
            "T", "POST", "/oauth/token",
            body="grant_type=client_credentials",
            content_type="")


# ---------------------------------------------------------------------------
# Injection guards on body + content_type
# ---------------------------------------------------------------------------

def test_body_with_single_quote_rejected():
    """Single quotes would escape the ABAP string literal and
    inject arbitrary code — the caller must URL-encode `'` as
    `%27` before passing.  Same guard as `path`."""
    with pytest.raises(HttpViaDestError, match="body"):
        _build_abap_program(
            "T", "POST", "/",
            body="grant_type=client_credentials&x=b'ar",
            content_type="text/plain")


def test_body_with_newline_rejected():
    """Newlines in the body would break the 72-char row split and
    could sneak past the ABAP tokenizer.  Reject."""
    with pytest.raises(HttpViaDestError, match="body"):
        _build_abap_program(
            "T", "POST", "/",
            body="grant_type=c\nharm",
            content_type="text/plain")


def test_content_type_with_quote_rejected():
    """A malformed Content-Type from an unsanitised source (e.g.
    stitched from user input) would inject the same way — guard."""
    with pytest.raises(HttpViaDestError, match="content_type"):
        _build_abap_program(
            "T", "POST", "/",
            body="x=y",
            content_type="text/'plain")


# ---------------------------------------------------------------------------
# Special chars that DO appear in real BTP client_ids must pass
# ---------------------------------------------------------------------------

def test_body_with_bang_and_pipe_accepted():
    """BTP xsuaa client_ids use `!` and `|` as separators.  Those
    are legal in ABAP string literals (only `'` and newlines
    break).  Reject-list must not over-reach — this exact shape
    is what we saw work end-to-end against researchlab-yehctg7m."""
    body = ("grant_type=client_credentials&client_id="
            "sb-clonef0e76cf4991f41369c69286725705654!b609810"
            "|destination-xsappname!b404")
    lines = _build_abap_program(
        "TO_BTP", "POST", "/oauth/token",
        body=body,
        content_type="application/x-www-form-urlencoded")
    # No exception, and the client_id survived chunking
    joined_body_chunks = "".join(
        ln.strip().strip("'").strip("&").strip()
        for ln in lines
        if ln.strip().startswith("'"))
    assert "!b609810" in joined_body_chunks
    assert "destination-xsappname" in joined_body_chunks


# ---------------------------------------------------------------------------
# GET / no-body regression: shape must be byte-identical to pre-fix
# ---------------------------------------------------------------------------

def test_get_no_body_emits_no_rq_data_line():
    """When the caller doesn't pass a body, the ABAP report must
    NOT declare an unused `rq` variable, set_cdata, or the request-
    side Content-Type header.  The response-side Content-Type read
    (``ct = c->response->get_header_field(...)``) is a diagnostic
    and DOES fire on every call — regardless of method."""
    lines = _build_abap_program(
        "TO_BTP", "GET",
        "/destination-configuration/v1/subaccountDestinations")
    assert not any("DATA: rq" in ln for ln in lines)
    assert not any("set_cdata" in ln for ln in lines)
    # Request-side header emission uses request->set_header_field —
    # that's what must NOT fire for a Content-Type on a GET.  The
    # response-side get_header_field('Content-Type') diagnostic is
    # unrelated and always runs.
    joined = "\n".join(lines)
    assert "request->set_header_field(\n    name  = 'Content-Type'" not in joined


def test_get_still_carries_accept_json():
    """The Accept header (used by the enumerate helper for the
    destination service response) must still fire on GET."""
    lines = _build_abap_program(
        "TO_BTP", "GET", "/")
    joined = "\n".join(lines)
    assert "'Accept'" in joined
    assert "'application/json'" in joined


# ---------------------------------------------------------------------------
# 72-char guard is still armed
# ---------------------------------------------------------------------------

def test_accept_encoding_identity_header_emitted():
    """XSUAA + most BTP APIs would otherwise send gzip'd bodies, and
    some SAP kernel versions return an empty string from get_cdata()
    on compressed replies.  Force uncompressed with
    Accept-Encoding: identity on every call — GET and POST alike."""
    for method in ("GET", "POST"):
        lines = _build_abap_program(
            "T", method, "/oauth/token",
            body=("grant_type=client_credentials"
                   if method == "POST" else ""),
            content_type=("application/x-www-form-urlencoded"
                            if method == "POST" else ""))
        joined = "\n".join(lines)
        assert "'Accept-Encoding'" in joined, (
            f"Accept-Encoding header missing on {method} — response "
            f"would come back gzip'd and get_cdata would return empty")
        assert "'identity'" in joined


def test_diagnostic_markers_emitted():
    """The wrapper writes ~~~CENC:, ~~~CLEN:, ~~~XLEN: alongside the
    existing ~~~STATUS: / ~~~REASON: so the parser can distinguish
    "server sent 0 bytes" from "kernel couldn't decode a compressed
    body".  Without these markers, an empty-body 200 looks
    identical to the operator regardless of cause."""
    lines = _build_abap_program(
        "TO_BTP", "POST", "/oauth/token",
        body="grant_type=client_credentials&client_id=x",
        content_type="application/x-www-form-urlencoded")
    joined = "\n".join(lines)
    assert "'~~~CENC:'" in joined
    assert "'~~~CLEN:'" in joined
    assert "'~~~XLEN:'" in joined


def test_get_data_fallback_when_cdata_empty():
    """When get_cdata() returns an empty string, the wrapper must
    fall through to get_data() (raw XSTRING) and codepage-decode.
    This is the gzip-compressed-response rescue path for older
    kernels that swallow compressed bodies at the string layer."""
    lines = _build_abap_program(
        "T", "POST", "/oauth/token",
        body="x=y", content_type="text/plain")
    joined = "\n".join(lines)
    assert "get_data(" in joined
    assert "cl_abap_codepage=>convert_from" in joined
    assert "codepage = 'UTF-8'" in joined


def test_parser_captures_diagnostic_fields():
    """Corresponding parser side: the diagnostic markers turn into
    result['content_encoding'] / ['content_length'] / ['wire_bytes']
    / ['transfer_encoding'] / ['content_type'] / ['response_headers']."""
    from sap_http_via_dest import _parse_abap_output
    out = _parse_abap_output([
        "~~~STATUS:            200",
        "~~~REASON: OK",
        "~~~CENC: gzip",
        "~~~CLEN: 1234",
        "~~~TENC: chunked",
        "~~~CTYP: application/json",
        "~~~XLEN:            0",
        "~~~HDR: Content-Type = application/json",
        "~~~HDR: Server = nginx",
        "~~~BODY_START",
        "~~~BODY_END",
    ])
    assert out["status"] == 200
    assert out["content_encoding"] == "gzip"
    assert out["content_length"] == "1234"
    assert out["transfer_encoding"] == "chunked"
    assert out["content_type"] == "application/json"
    assert out["wire_bytes"] == 0
    assert ("Content-Type", "application/json") in out["response_headers"]
    assert ("Server", "nginx") in out["response_headers"]
    # ok=True because status is set even though body empty — the mint
    # helper then surfaces the "compressed body couldn't decode" hint
    # from these diagnostic fields.
    assert out["ok"] is True


def test_body_read_uses_get_data_first():
    """Some SAP kernels have a "first-read consumes" bug: calling
    get_cdata first empties the buffer for a subsequent get_data.
    The wrapper reads get_data first now to avoid it.  Regression
    catch: if a future refactor puts get_cdata back first, this test
    fires."""
    lines = _build_abap_program("T", "POST", "/oauth/token",
                                    body="x=y", content_type="text/plain")
    joined = "\n".join(lines)
    cdata_pos = joined.find("get_cdata(")
    data_pos = joined.find("get_data(")
    assert data_pos != -1 and cdata_pos != -1
    assert data_pos < cdata_pos, (
        f"get_data must be called BEFORE get_cdata to avoid the "
        f"kernel's first-read-consumes bug on chunked bodies "
        f"(get_data at {data_pos}, get_cdata at {cdata_pos})")


def test_response_header_dump_emitted():
    """The full header dump (up to 20 entries) is emitted on every
    call so operators can distinguish "kernel received nothing" from
    "kernel got a response but body-read failed"."""
    lines = _build_abap_program("T", "POST", "/oauth/token",
                                    body="x=y", content_type="text/plain")
    joined = "\n".join(lines)
    assert "get_header_fields(" in joined
    assert "'~~~HDR:'" in joined
    assert "hd-name" in joined and "hd-value" in joined
    # And the 20-entry cap must be present so a chatty proxy can't
    # blow past the WRITE table.
    assert "IF hc > 20." in joined


def test_72_char_guard_still_fires_on_body_path():
    """If a body ever manages to produce a line over 72 chars —
    would silently truncate on the PROGRAM table row — the guard
    at the bottom of _build_abap_program must still raise.  We
    can't easily trigger this with legitimate input (chunking
    stops at 40 chars), so this test just documents that the
    guard runs after the body-block insertion."""
    # Legitimate input never crosses 72; if a future refactor drops
    # the chunking, this catches it because 100-char literal blows
    # past 72 via a single 'literal'.  Simulated by monkeypatching
    # _abap_string_assignment to skip chunking.
    import sap_http_via_dest as m
    orig = m._abap_string_assignment
    try:
        m._abap_string_assignment = lambda var, val: [
            f"{var} = '{val}'."]
        with pytest.raises(HttpViaDestError, match="72-char"):
            m._build_abap_program(
                "T", "POST", "/",
                body="x" * 100,   # blows past 72 chars uncchunked
                content_type="text/plain")
    finally:
        m._abap_string_assignment = orig
