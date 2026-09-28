"""Pure-Python RFC backend — wraps saprfclib with the same interface as
sap_rfc_ctypes.RFCConnection so that every call site in SAPMAP works
unchanged.

saprfclib requires Python 3.12+.  On older interpreters this module
will fail to import, and SAPMAP falls back to the C SDK automatically.

Requires saprfclib >= 0.1.5.  Every bug surfaced during integration is now
fixed upstream (randomstr1ng/saprfclib), so this adapter carries no
workarounds — it wraps the public interface directly.

Upstream fixes that this adapter used to work around (all now resolved):

    #7  RFCPING response parse failure on kernel 793
    #8  connect() rejected the `lang` kwarg
    #9  TABLE params misclassified as RFCTYPE_STRUCTURE — encode/decode crash
    #10 TABLE params carried rfctype=STRUCTURE in auto-fetched FunctionDesc
    #11 _encode_structure raised KeyError for partial row dicts
    #12 _call_bootstrap only fetched type_desc when rfctype==STRUCTURE
    #24 Connection.call() raised ValueError on unknown kwargs — fixed in
        v0.1.2: connect(strict_params=False) (the default) now drops
        unrecognised kwargs, matching pyrfc / the C SDK.
    #30 TLV frame footer overflowed the 16-bit length for bodies > 64KB
        (large ABAP INSTALL_AND_RUN payloads etc.) — fixed in v0.1.2:
        tlv_record() now emits the extended uint32 length form.

If you see regressions, `pip3 install --upgrade saprfclib` first.
"""

import datetime
import inspect
import logging
import traceback as _tb

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import saprfclib — fast-fail if it is not installed
# ---------------------------------------------------------------------------

import saprfclib as _lib
from saprfclib import (
    FunctionDesc  as _FunctionDesc,
    TypeDesc      as _TypeDesc,
    FieldDesc     as _FieldDesc,
)

# ---------------------------------------------------------------------------
# Constants — identical numeric values to sap_rfc_ctypes
# ---------------------------------------------------------------------------

RFCTYPE_CHAR      = 0
RFCTYPE_DATE      = 1
RFCTYPE_BCD       = 2
RFCTYPE_TIME      = 3
RFCTYPE_BYTE      = 4
RFCTYPE_TABLE     = 5
RFCTYPE_NUM       = 6
RFCTYPE_FLOAT     = 7
RFCTYPE_INT       = 8
RFCTYPE_INT2      = 9
RFCTYPE_INT1      = 10
RFCTYPE_NULL      = 14
RFCTYPE_STRUCTURE = 17
RFCTYPE_DECF16    = 23
RFCTYPE_DECF34    = 24
RFCTYPE_STRING    = 29
RFCTYPE_XSTRING   = 30
RFCTYPE_INT8      = 31
RFCTYPE_UTCLONG   = 32

RFC_IMPORT   = 0x01
RFC_EXPORT   = 0x02
RFC_CHANGING = 0x03
RFC_TABLES   = 0x07

# ---------------------------------------------------------------------------
# Exception hierarchy — mirrors sap_rfc_ctypes exactly
# ---------------------------------------------------------------------------

class RFCError(Exception):
    """Base exception for SAP RFC errors."""
    def __init__(self, message='', code=0, key='', group=0,
                 msg_class='', msg_type='', msg_number='',
                 msg_v1='', msg_v2='', msg_v3='', msg_v4=''):
        self.code = code
        self.key = key
        self.group = group
        self.msg_class = msg_class
        self.msg_type = msg_type
        self.msg_number = msg_number
        self.msg_v1 = msg_v1
        self.msg_v2 = msg_v2
        self.msg_v3 = msg_v3
        self.msg_v4 = msg_v4
        super().__init__(message)


class CommunicationError(RFCError):
    """Network or communication failure."""
    pass


class LogonError(RFCError):
    """Authentication/logon failure."""
    pass


class ABAPApplicationError(RFCError):
    """ABAP application exception (raised by RAISE in the function module)."""
    pass


class ABAPRuntimeError(RFCError):
    """ABAP runtime error (short dump on the server)."""
    pass


class ExternalError(RFCError):
    """Error in external (non-SAP) code."""
    pass


# ---------------------------------------------------------------------------
# Exception mapping — saprfclib exception → SAPMAP exception
# ---------------------------------------------------------------------------

def _translate_exception(exc):
    """Convert a saprfclib exception into the matching SAPMAP exception."""
    kwargs = {}
    for attr in ('key', 'msg_class', 'msg_type', 'msg_number',
                 'msg_v1', 'msg_v2', 'msg_v3', 'msg_v4'):
        kwargs[attr] = getattr(exc, attr, '') or ''

    message = str(exc)

    if isinstance(exc, _lib.AbapApplicationError):
        return ABAPApplicationError(message, **kwargs)
    if isinstance(exc, _lib.CommunicationError):
        return CommunicationError(message, **kwargs)
    if hasattr(_lib, 'AbapSystemFailure') and isinstance(exc, _lib.AbapSystemFailure):
        return ABAPRuntimeError(message, **kwargs)
    if hasattr(_lib, 'LogonError') and isinstance(exc, _lib.LogonError):
        return LogonError(message, **kwargs)
    return RFCError(message, **kwargs)


# ---------------------------------------------------------------------------
# Discover which params saprfclib.connect() actually accepts (varies by
# version) so we can silently drop unsupported ones.  Defensive belt —
# doesn't hide bugs, just keeps SAPMAP running when saprfclib adds or
# removes a kwarg.
# ---------------------------------------------------------------------------

_SAPRFCLIB_PARAMS = frozenset(
    inspect.signature(_lib.connect).parameters.keys()
)


# ---------------------------------------------------------------------------
# Result normalization — saprfclib → C-SDK-compatible format
# ---------------------------------------------------------------------------

def _normalize_result(result):
    """Convert saprfclib call results to match the C SDK's return format.

    saprfclib converts DATE/TIME fields to datetime.date/datetime.time
    objects.  The C SDK returns raw strings ("YYYYMMDD" / "HHMMSS").
    SAPMAP code expects strings, so we convert back.
    """
    if isinstance(result, dict):
        return {k: _normalize_value(v) for k, v in result.items()}
    return result


def _normalize_value(val):
    if isinstance(val, datetime.date) and not isinstance(val, datetime.datetime):
        return val.strftime('%Y%m%d')
    if isinstance(val, datetime.time):
        return val.strftime('%H%M%S')
    if isinstance(val, dict):
        return {k: _normalize_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_normalize_value(item) for item in val]
    return val


# ---------------------------------------------------------------------------
# RFCConnection — drop-in replacement for sap_rfc_ctypes.RFCConnection
# ---------------------------------------------------------------------------

class RFCConnection:
    """Pure-Python RFC connection backed by saprfclib.

    Interface-compatible with sap_rfc_ctypes.RFCConnection so every
    caller in SAPMAP works without changes.
    """

    def __init__(self, sdk_path=None, **params):
        # sdk_path is accepted but ignored — no native library needed
        self._params = params
        self._conn = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # -- Connection lifecycle --

    def open(self):
        if self._conn is not None:
            return
        filtered = {k: v for k, v in self._params.items()
                    if k in _SAPRFCLIB_PARAMS}
        dropped = set(self._params) - set(filtered)
        if dropped:
            logger.debug('saprfclib: dropped unsupported params: %s', dropped)
        # saprfclib expects sysnr as int (SAPMAP stores it as str)
        if 'sysnr' in filtered:
            try:
                filtered['sysnr'] = int(filtered['sysnr'])
            except (ValueError, TypeError):
                pass
        try:
            self._conn = _lib.connect(**filtered)
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e
        except Exception as e:
            raise RFCError(f"saprfclib connect failed: {e}") from e
        logger.info('RFC connection opened (pure-python)')

    def close(self):
        if self._conn is None:
            return
        try:
            self._conn.close()
        except Exception:
            pass
        self._conn = None
        logger.info('RFC connection closed (pure-python)')

    @property
    def is_open(self):
        if self._conn is None:
            return False
        try:
            return bool(self._conn.ping())
        except Exception:
            return False

    def ping(self):
        if self._conn is None:
            return False
        try:
            return bool(self._conn.ping())
        except Exception as e:
            logger.debug('saprfclib ping() raised: %s', e)
            return False

    def ping_verbose(self):
        if self._conn is None:
            return (False, "RFC_INVALID_HANDLE", "connection is closed")
        try:
            ok = self._conn.ping()
            if ok:
                return (True, "", "")
            return (False, "", "saprfclib ping() returned False")
        except _lib.AbapApplicationError as e:
            key = getattr(e, 'key', '') or ''
            return (False, key, str(e))
        except _lib.SapRfcError as e:
            key = getattr(e, 'key', '') or ''
            return (False, key, str(e))
        except Exception as e:
            return (False, type(e).__name__, str(e))

    # Connection-attribute keys SAPMAP callers read are the C-SDK / pyrfc
    # camelCase names (sysId, partnerHost, kernelRel, ...).  saprfclib's
    # ConnectionAttributes exposes snake_case fields (sys_id, partner_host,
    # kernel_rel, ...), so map each canonical key from whichever spelling the
    # backend provides — keeping get_attributes() a drop-in for the C SDK.
    _ATTR_ALIASES = (
        ("dest",                ("dest",)),
        ("host",                ("host",)),
        ("partnerHost",         ("partner_host", "partnerHost")),
        ("sysNumber",           ("sys_number", "sysNumber")),
        ("sysId",               ("sys_id", "sysId")),
        ("client",              ("client",)),
        ("user",                ("user",)),
        ("language",            ("language",)),
        ("isoLanguage",         ("iso_language", "isoLanguage")),
        ("codepage",            ("codepage",)),
        ("partnerCodepage",     ("partner_codepage", "partnerCodepage")),
        ("rfcRole",             ("rfc_role", "rfcRole")),
        ("type",                ("type",)),
        ("partnerType",         ("partner_type", "partnerType")),
        ("rel",                 ("rel",)),
        ("partnerRel",          ("partner_rel", "partnerRel")),
        ("kernelRel",           ("kernel_rel", "kernelRel")),
        ("partnerBytesPerChar", ("partner_bytes_per_char", "partnerBytesPerChar")),
        ("partnerIP",           ("partner_ip", "partnerIP")),
        ("partnerIPv6",         ("partner_ipv6", "partnerIPv6")),
    )

    def get_attributes(self):
        self._ensure_open()
        try:
            attrs = self._conn.get_connection_attributes()
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e

        def _read(src, name):
            return src.get(name) if isinstance(attrs, dict) \
                else getattr(src, name, None)

        result = {}
        for canonical, aliases in self._ATTR_ALIASES:
            for name in aliases:
                val = _read(attrs, name)
                if val is not None and str(val).strip():
                    result[canonical] = str(val).strip()
                    break
        return result

    # -- RFC Function Invocation --

    def call(self, func_name, **kwargs):
        # saprfclib >= 0.1.2 defaults to connect(strict_params=False), so
        # unknown kwargs are dropped like pyrfc / the C SDK, and tlv_record()
        # encodes > 64KB bodies via the extended uint32 length form — no
        # adapter-side workarounds are needed for either any more.
        self._ensure_open()
        try:
            result = self._conn.call(func_name, **kwargs)
            return _normalize_result(result)
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e
        except Exception as e:
            tb_str = _tb.format_exc()
            logger.debug(
                "saprfclib call(%s) internal error: %s\n%s",
                func_name, e, tb_str)
            raise RFCError(f"saprfclib call({func_name}) failed: {e}") from e

    def _make_type_desc(self, name, fields):
        """Create a type description manually.

        Args:
            name: type name (e.g. "TAB200")
            fields: list of (field_name, rfctype, nuc_length, uc_length)

        rfctype is a numeric RFCTYPE_* constant (same contract as the C-SDK
        adapter).  saprfclib's FieldDesc / TypeDesc take the numeric type and
        explicit field offsets / row sizes, so we accumulate offsets and set
        the total non-unicode / unicode row widths just like the C SDK does.
        """
        field_descs = []
        nuc_offset = 0
        uc_offset = 0
        for fname, ftype, nuc_len, uc_len in fields:
            field_descs.append(_FieldDesc(
                name=fname,
                rfctype=ftype,
                nuc_length=nuc_len,
                nuc_offset=nuc_offset,
                uc_length=uc_len,
                uc_offset=uc_offset,
                decimals=0,
            ))
            nuc_offset += nuc_len
            uc_offset += uc_len
        return _TypeDesc(name=name, fields=field_descs,
                         nuc_size=nuc_offset, uc_size=uc_offset)

    def _make_func_desc(self, func_name, params):
        """Create a function description manually.

        Args:
            func_name: FM name
            params: list of (name, direction, rfctype, uc_length,
                    nuc_length, type_desc_handle) tuples

        direction is a numeric RFC_* constant and rfctype a numeric RFCTYPE_*
        constant (same contract as the C-SDK adapter); saprfclib's FieldDesc
        takes both as ints directly.
        """
        param_descs = []
        for pname, direction, ptype, uc_len, nuc_len, td_handle in params:
            param_descs.append(_FieldDesc(
                name=pname,
                rfctype=ptype,
                nuc_length=nuc_len,
                nuc_offset=0,
                uc_length=uc_len,
                uc_offset=0,
                decimals=0,
                direction=direction,
                type_desc=td_handle,
                optional=True,
            ))
        return _FunctionDesc(name=func_name, parameters=param_descs)

    def call_raw(self, func_name, func_desc, **kwargs):
        """Call using a manually-built function description.

        saprfclib always auto-fetches metadata from the server, so the
        func_desc is only used as fallback when the auto-fetch fails.
        """
        self._ensure_open()
        try:
            result = self._conn.call(func_name, **kwargs)
            return _normalize_result(result)
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e
        except Exception as e:
            tb_str = _tb.format_exc()
            logger.debug(
                "saprfclib call_raw(%s) internal error: %s\n%s",
                func_name, e, tb_str)
            raise RFCError(
                f"saprfclib call_raw({func_name}) failed: {e}") from e

    # -- Internal --

    def _ensure_open(self):
        if self._conn is None:
            raise RFCError("Connection is not open — call open() first")
