"""Regression tests for ``classify_login_response`` — DIAG-response
classifier used by the default-credentials probe.

Issue #36 regression: German responses were misclassified as SUCCESS
because (a) every text pattern was English-only and (b) the fallback
"E: <text>" regex required the preceding DIAG length byte to be
non-alphabetic — but that byte is the length of the following string
and can accidentally land in 0x41-0x5A ('A'-'Z'), which is exactly
what happens with the ~71-character German error string
"Name oder Kennwort ist nicht korrekt (Wiederholen Sie die Anmeldung)"
whose length byte is 0x47 = 'G'.
"""
from sap_default_creds import (
    classify_login_response, SUCCESS, WRONG_PASSWORD, PASSWORD_CHANGE,
    USER_LOCKED, USER_NOT_EXIST, CLIENT_UNAVAIL, NO_AUTH_LOGON,
)


# The exact German DIAG response captured in issue #36.  Includes:
#   * German error text with length byte 0x47 = 'G' (breaks the
#     old [^A-Za-z]E:  anchor)
#   * SAP message class+number triple E\x00 00 \x00 152 \x00
#   * Login-screen input fields RSYST-MANDT / -BNAME / -BCODE / -LANGU
_GERMAN_WRONG_PW = (
    b"\x00\x00\x00\x00\x00\x01\x00\x00\x10\x06\x11\x00 "
    b"\xef\x7f\xfe-\xd8\xb77\xd6t\x08~\x13\x05\x97\x15\x97"
    b"\xef\xf2?\x8d\x03p\xff\x0f\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x10\x06#\x00\x0f\x00\x00\x10\x0e\x014110\x00UTF8\x00"
    b"\x10\x06'\x00 \x00\x00\x10\x07\x024103\x00UnicodeLittleUnmarked\x00"
    b"\x10\x06!\x00 66A665A064091FD1A6C5BC77F7A8C000"
    b"\x10\x06\x02\x00\x03QHC\x10\x06\x03\x00\x0ckfw-qhc-lt27"
    b"\x10\x06\x0b\x00G"
    b"E: Name oder Kennwort ist nicht korrekt "
    b"(Wiederholen Sie die Anmeldung)"
    b"\x10\x0c\x03\x00\x1dE\x0000 \x00152\x00 \x00"
    b"RSYST-MANDT\x00RSYST-BNAME\x00RSYST-BCODE\x00RSYST-LANGU\x00"
    # Pad past the 200-byte size threshold so the size heuristic
    # would fire if all other detections failed.
    + b"\x00" * 200
)


def test_issue_36_german_wrong_password_not_misclassified_as_success():
    """Bug: German response with length-byte-accident used to
    return SUCCESS from the size heuristic.  Must be WRONG_PASSWORD."""
    result, detail = classify_login_response(_GERMAN_WRONG_PW)
    assert result == WRONG_PASSWORD, (
        f"expected WRONG_PASSWORD, got {result} ({detail!r})")


def test_language_independent_msg_00_152_beats_size_heuristic():
    """Even without the E: text (edge case), the numbered-message
    pattern E\\x00 00 \\x00 152 \\x00 alone should mark the response
    as WRONG_PASSWORD."""
    resp = (b"\x00" * 100
             + b"\x10\x0c\x03\x00\x1dE\x0000 \x00152\x00 \x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == WRONG_PASSWORD


def test_language_independent_msg_00_042_user_locked():
    resp = (b"\x00" * 100
             + b"\x10\x0c\x03\x00\x1dE\x0000 \x00042\x00 \x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == USER_LOCKED


def test_language_independent_msg_00_198_user_not_exist():
    resp = (b"\x00" * 100
             + b"\x10\x0c\x03\x00\x1dE\x0000 \x00198\x00 \x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == USER_NOT_EXIST


def test_language_independent_msg_00_197_client_unavail():
    resp = (b"\x00" * 100
             + b"\x10\x0c\x03\x00\x1dE\x0000 \x00197\x00 \x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == CLIENT_UNAVAIL


def test_login_screen_fields_present_means_rejected():
    """If RSYST-BNAME / -BCODE / -MANDT / -LANGU appear in the
    response, the server is re-rendering the logon dynpro — a
    successful logon lands on SAP Easy Access which contains none
    of these fields.  Without the numbered-message and without any
    text pattern, this alone must NOT flip to SUCCESS via the size
    heuristic."""
    resp = (b"\x00" * 300
             + b"RSYST-MANDT\x00RSYST-BNAME\x00RSYST-BCODE\x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == WRONG_PASSWORD


def test_english_wrong_password_still_matches():
    """Backwards compatibility — the original English text patterns
    must still fire on English DIAG responses."""
    resp = (b"\x00\x00\x10\x06"
             + b"\xffE: Name or password is incorrect"
             + b" (repeat logon)\x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == WRONG_PASSWORD


def test_english_user_locked_still_matches():
    resp = (b"\x00" * 100
             + b"E: User SAPMAP00 is locked\x00"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    assert result == USER_LOCKED


def test_empty_response_is_error():
    result, _ = classify_login_response(b"")
    assert result != SUCCESS


def test_short_response_below_200_is_inconclusive():
    """Short responses with no error markers used to fall through to
    'inconclusive' — must not become SUCCESS."""
    resp = b"\x00\x10\x06" + b"\x00" * 50
    result, _ = classify_login_response(resp)
    assert result != SUCCESS


def test_length_byte_accident_no_longer_masks_error():
    """The exact anti-pattern from issue #36: an E: error whose
    preceding DIAG length byte is an ASCII letter must still be
    detected as an error by the generic 'E: <text>' fallback
    (even in the pathological case where the numbered-message and
    text-pattern branches all miss)."""
    # Length byte 0x47 ('G') then E: with an unknown language message.
    resp = (b"\x00" * 50
             + b"\x10\x06\x0b\x00G"
             + b"E: Nazwa lub haslo sa niepoprawne (Polish)"
             + b"\x00" * 200)
    result, _ = classify_login_response(resp)
    # Should NOT be SUCCESS — the generic E: fallback catches it
    # even without a Polish text pattern.
    assert result != SUCCESS
