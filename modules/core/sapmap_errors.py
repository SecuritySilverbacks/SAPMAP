"""Shared formatter for SAP RFC / pyrfc exceptions.

pyrfc raises ``ABAPApplicationError`` / ``ABAPRuntimeError`` /
``CommunicationError`` / etc.  All of them subclass ``RFCError`` and
expose rich attributes (``key``, ``message``, ``msg_class``,
``msg_number``, ``msg_type``, ``msg_v1`` … ``msg_v4``) — but
``str(exc)`` often collapses to the unhelpful ``RFC_ABAP_EXCEPTION:
Number:000`` form, swallowing the actual error name.

This helper extracts every populated attribute so an operator can tell
``NOT_AUTHORIZED`` from ``FIELD_NOT_VALID`` from ``DATA_BUFFER_EXCEEDED``
at a glance.  Non-pyrfc exceptions degrade cleanly to ``str(exc)`` — so
the helper is safe to drop into any ``except Exception`` block.
"""
from __future__ import annotations


_PYRFC_ATTRS = ("key", "message", "msg_class", "msg_number",
                "msg_type", "msg_v1", "msg_v2", "msg_v3", "msg_v4")


def format_rfc_exception(exc: BaseException) -> str:
    """Return a single-line, operator-readable rendering of a pyrfc error.

    Examples:
        ``ABAPApplicationError: RFC_ABAP_EXCEPTION: Number:000
         [key=FIELD_NOT_VALID, msg_number=000]``
        ``CommunicationError: connect to message server failed``
        ``ValueError: bad escape``  (non-pyrfc fallback)
    """
    extras = []
    for attr in _PYRFC_ATTRS:
        v = getattr(exc, attr, None)
        if v:
            extras.append(f"{attr}={v}")
    base = f"{type(exc).__name__}: {exc}"
    if extras:
        return base + "  [" + ", ".join(extras) + "]"
    return base
