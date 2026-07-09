"""Kernel-proxied HTTP-over-RFC — the exploit primitive that makes
certificate-authenticated Type-G destinations lateral-move material.

Pin down the ABAP-report generation (no injection surface), the
output parser (extracts status + body from WRITE-format lines), and
the BTP subaccount-destinations enumeration on top of the primitive.
"""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import modules  # noqa: F401  (registers package paths)
from sap_http_via_dest import (
    HttpViaDestError,
    _build_abap_program,
    _parse_abap_output,
    _validate_destination_name,
    call_via_destination,
    enumerate_btp_subaccount_destinations,
)
from sapmap_models import SAPNode


def _node():
    return SAPNode(sid="AE1", ip="10.10.1.6")


# ---------------------------------------------------------------------------
# _validate_destination_name — trust boundary
# ---------------------------------------------------------------------------

def test_valid_destination_names_accepted():
    """SM59 rules: uppercase letters, digits, underscore, dot, slash,
    up to 32 chars.  These must pass so real destinations work."""
    for name in ["TEST_MARCH", "HTTPS_FORTINET_TEST",
                    "AE1_TO_BTP", "SAP/HTTP.G1", "A" * 32]:
        _validate_destination_name(name)  # no raise


def test_destination_name_with_quote_rejected():
    """The destination name is spliced into an ABAP string literal
    via RFC_ABAP_INSTALL_AND_RUN.  A single quote would escape the
    literal and let the caller inject arbitrary ABAP.  This test
    pins down the guard — if it ever regresses, someone can burn a
    system by feeding a malicious destination name into the primitive.
    """
    for bad in ["EVIL'INJECT", 'BAD"NAME',
                  "WITH SPACE", "TOO_LONG" + "X" * 100,
                  "NEWLINE\nHERE", "", "OK'; WRITE:'"]:
        try:
            _validate_destination_name(bad)
        except HttpViaDestError:
            continue
        raise AssertionError(
            f"expected HttpViaDestError for {bad!r} — got no raise")


def test_path_with_quote_rejected():
    """Same rationale as the destination name: the path goes into an
    ABAP string literal for ``set_header_field( '~request_uri' = '…' )``.
    Attacker-controlled paths carrying a single quote must be
    rejected upfront."""
    try:
        _build_abap_program("TEST_MARCH", "GET", "/evil'; WRITE:'x'")
    except HttpViaDestError:
        return
    raise AssertionError("expected HttpViaDestError for path with quote")


def test_unsupported_method_rejected():
    """Only known HTTP verbs — random strings could otherwise land in
    the generated ``set_method( '…' )`` call, causing the ABAP to
    reject the report at compile time (confusing operator error)."""
    try:
        _build_abap_program("TEST_MARCH", "TRACE_ROUTE", "/")
    except HttpViaDestError:
        return
    raise AssertionError("expected HttpViaDestError for weird method")


# ---------------------------------------------------------------------------
# _build_abap_program — generated ABAP source
# ---------------------------------------------------------------------------

def test_abap_program_uses_create_by_destination():
    """The whole point of the primitive: the report must call
    cl_http_client=>create_by_destination with the destination name
    embedded verbatim.  Anything else would be a different attack."""
    prog = _build_abap_program("TEST_MARCH", "GET",
                                  "/destination-configuration/v1/"
                                  "subaccountDestinations")
    joined = "\n".join(prog)
    assert "cl_http_client=>create_by_destination(" in joined
    assert "destination = 'TEST_MARCH'" in joined
    assert "set_method( 'GET' )" in joined
    assert ("set_header_field( name = '~request_uri' value = "
              "'/destination-configuration/v1/subaccountDestinations' )"
              in joined)


def test_abap_program_chunks_body_within_zeile_width():
    """RFC_ABAP_INSTALL_AND_RUN's WRITES table is 256-char wide;
    chunking to ~200 char keeps some safety margin and prevents
    quiet truncation of long JSON bodies (BTP responses easily
    exceed 256 chars per line)."""
    prog = _build_abap_program("TEST_MARCH", "GET", "/")
    joined = "\n".join(prog)
    # The loop MUST split into 200-char chunks; if this drifts back
    # to writing the whole body in one WRITE, we'll silently truncate
    # every BTP response body.
    assert "lv_take > 200" in joined or "lv_take = 200" in joined


# ---------------------------------------------------------------------------
# _parse_abap_output — WRITE-format → structured dict
# ---------------------------------------------------------------------------

def test_parse_happy_path_200():
    """A clean 200 response with a two-chunk body must be re-joined
    exactly.  This is the mainline case for every BTP call."""
    out = [
        "~~~STATUS: 200",
        "~~~REASON: OK",
        "~~~BODY_START",
        "~~~BOD: {\"first_half\":\"aaaaa\",",
        "~~~BOD: \"second_half\":\"bbbbb\"}",
        "~~~BODY_END",
    ]
    r = _parse_abap_output(out)
    assert r["ok"] is True
    assert r["status"] == 200
    assert r["reason"] == "OK"
    assert r["body"] == '{"first_half":"aaaaa","second_half":"bbbbb"}'
    assert r["error"] == ""


def test_parse_create_by_destination_failure_surfaces_error():
    """When the SAP kernel refuses the destination (bad SSL PSE, no
    such destination, etc.) the ABAP emits ``~~~ERR:`` with sy-subrc.
    We must surface it to the operator instead of silently returning
    a 200 with empty body."""
    out = ["~~~ERR: create_by_destination sy-subrc=", "2"]
    r = _parse_abap_output(out)
    assert r["ok"] is False
    assert "create_by_destination" in r["error"]


def test_parse_no_markers_reports_diagnostic():
    """When the ABAP report doesn't even install (compile error /
    S_DEVELOP denied), the returned lines carry no markers.  Rather
    than silently succeed with empty body, we must produce a clear
    diagnostic."""
    r = _parse_abap_output(["random ABAP compile error output"])
    assert r["ok"] is False
    assert "install" in r["error"].lower()


# ---------------------------------------------------------------------------
# call_via_destination — top-level orchestration
# ---------------------------------------------------------------------------

def _fake_abap_success(status=200, reason="OK", body=""):
    """Build a fake _run_abap_program result matching the parser's
    expected WRITE-format."""
    lines = [
        f"~~~STATUS: {status}",
        f"~~~REASON: {reason}",
        "~~~BODY_START",
    ]
    for i in range(0, len(body), 200):
        lines.append(f"~~~BOD: {body[i:i+200]}")
    lines.append("~~~BODY_END")
    return {"success": True, "output": lines, "error": ""}


def test_call_via_destination_rejects_bad_name_before_rfc():
    """A malicious destination name must be rejected upfront —
    NOT after sending the ABAP report to the target.  Prevents
    accidental injection attempts from ever hitting the kernel."""
    try:
        call_via_destination(_node(), "EVIL'INJECT")
    except HttpViaDestError:
        return
    raise AssertionError("expected HttpViaDestError for bad name")


def test_call_via_destination_returns_body_on_200():
    """Mainline: call_via_destination returns the ABAP-side result
    parsed into a dict.  Uses the real _parse_abap_output so any
    parser drift is caught."""
    body = '{"hello":"world"}'
    with patch("sapmap_rfc._get_connection") as gc, \
         patch("sapmap_rfc._run_abap_program",
                 return_value=_fake_abap_success(body=body)):
        gc.return_value.__enter__ = MagicMock(return_value=MagicMock())
        gc.return_value.__exit__ = MagicMock(return_value=False)
        r = call_via_destination(_node(), "TEST_MARCH", path="/foo")

    assert r["ok"] is True
    assert r["status"] == 200
    assert r["body"] == body


# ---------------------------------------------------------------------------
# BTP subaccount destinations enumeration
# ---------------------------------------------------------------------------

def test_enumerate_btp_flags_cleartext_password():
    """The exploitation payoff — when the BTP destination service
    hands back a destination with a cleartext Password field, we
    must surface it as loot.  This is the on-prem → cloud → on-prem
    lateral move closure."""
    btp_body = json.dumps([
        {
            "Name": "ONPREM_SVC_A",
            "URL": "http://backend.internal:8080",
            "User": "SVC_USER",
            "Password": "hunter2",
            "Authentication": "BasicAuthentication",
        },
        {
            "Name": "PUBLIC_HTTPS",
            "URL": "https://public-api.example.com",
            "Authentication": "NoAuthentication",
        },
    ])
    with patch("sapmap_rfc._get_connection") as gc, \
         patch("sapmap_rfc._run_abap_program",
                 return_value=_fake_abap_success(body=btp_body)):
        gc.return_value.__enter__ = MagicMock(return_value=MagicMock())
        gc.return_value.__exit__ = MagicMock(return_value=False)
        r = enumerate_btp_subaccount_destinations(
            _node(), "TEST_MARCH")

    assert r["ok"] is True
    assert r["count"] == 2
    assert len(r["cleartext"]) == 1
    hit = r["cleartext"][0]
    assert hit["name"] == "ONPREM_SVC_A"
    assert hit["field"] == "Password"


def test_enumerate_btp_handles_wrapped_response_shape():
    """Some BTP kernels wrap the array as {"destinations": [...]}
    rather than returning a bare list.  Both shapes must parse."""
    body = json.dumps({"destinations": [
        {"Name": "A", "Authentication": "NoAuthentication"},
    ]})
    with patch("sapmap_rfc._get_connection") as gc, \
         patch("sapmap_rfc._run_abap_program",
                 return_value=_fake_abap_success(body=body)):
        gc.return_value.__enter__ = MagicMock(return_value=MagicMock())
        gc.return_value.__exit__ = MagicMock(return_value=False)
        r = enumerate_btp_subaccount_destinations(
            _node(), "TEST_MARCH")

    assert r["ok"] is True
    assert r["count"] == 1


def test_enumerate_btp_reports_non_200_status():
    """403 / 401 / 5xx from the destination service must surface as
    a specific error rather than a silent "no destinations" result —
    otherwise the operator can't tell "cert-auth failed" from
    "subaccount has no destinations"."""
    with patch("sapmap_rfc._get_connection") as gc, \
         patch("sapmap_rfc._run_abap_program",
                 return_value=_fake_abap_success(
                     status=403, reason="Forbidden", body="")):
        gc.return_value.__enter__ = MagicMock(return_value=MagicMock())
        gc.return_value.__exit__ = MagicMock(return_value=False)
        r = enumerate_btp_subaccount_destinations(
            _node(), "TEST_MARCH")

    assert r["ok"] is False
    assert "403" in r["error"]
    assert "Forbidden" in r["error"]
