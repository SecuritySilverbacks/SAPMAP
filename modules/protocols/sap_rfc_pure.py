"""Pure-Python RFC backend — wraps saprfclib with the same interface as
sap_rfc_ctypes.RFCConnection so that every call site in SAPMAP works
unchanged.

saprfclib requires Python 3.12+.  On older interpreters this module
will fail to import, and SAPMAP falls back to the C SDK automatically.
"""

import datetime
import logging
import traceback as _tb
from struct import error as struct_error

logger = logging.getLogger(__name__)

import sys as _sys
_sys.stderr.write("[DBG-STDERR] sap_rfc_pure module is being imported\n")
_sys.stderr.flush()
print("[DBG] sap_rfc_pure module is being imported", flush=True)

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
# Monkey-patch: saprfclib classifies TABLE-direction params as
# RFCTYPE_STRUCTURE (17) in the auto-fetched FunctionDesc.  This causes
# two problems:
#   1. encode() calls _encode_structure() on a list[dict] → crash
#   2. The TLV tag says STRUCTURE but the data is TABLE → server rejects
#      with CALL_FUNCTION_ILLEGAL_P_TYPE
#   3. decode() returns a single dict instead of list[dict] → empty results
#
# Root fix: patch Connection.call() to correct rfctype on TABLE-direction
# params (17→5) in the FunctionDesc BEFORE invoke uses it.  This fixes
# TLV tags, encode dispatch, AND decode dispatch in one place.
#
# Also patch codec.encode to pad missing fields with type-appropriate
# defaults (C SDK fills them; saprfclib requires all fields present).
# ---------------------------------------------------------------------------

try:
    from saprfclib import codec as _codec
    from saprfclib import invoke as _invoke

    _original_encode = _codec.encode
    _original_decode = _codec.decode

    # -- Direction detection (handles str, int, enum) --

    def _is_table_direction(direction):
        if isinstance(direction, str):
            return 'TABLE' in direction.upper()
        if isinstance(direction, int):
            return direction == 7
        name = getattr(direction, 'name', '')
        if isinstance(name, str) and 'TABLE' in name.upper():
            return True
        val = getattr(direction, 'value', None)
        if isinstance(val, int) and val == 7:
            return True
        return False

    # -- Metadata fix: TABLE params rfctype 17→5 --

    def _fix_table_params(func_desc):
        params = getattr(func_desc, 'parameters', None)
        if params is None:
            return
        for param in params:
            if _is_table_direction(getattr(param, 'direction', '')):
                if getattr(param, 'rfctype', 0) == 17:
                    try:
                        param.rfctype = 5
                    except (AttributeError, TypeError):
                        pass

    from saprfclib import connection as _conn_mod

    def _fix_table_rfctype_post(desc, ctx=""):
        """Change TABLE-direction params from rfctype 17 (STRUCTURE) to 5
        (TABLE) AFTER _call_bootstrap has attached type_desc via the
        STRUCTURE lookup path."""
        fixed = []
        for p in getattr(desc, 'parameters', []):
            if (_is_table_direction(getattr(p, 'direction', 0))
                    and getattr(p, 'rfctype', 0) == 17):
                p.rfctype = 5
                fixed.append(p.name)
        if fixed:
            _sys.stderr.write(
                f"[DBG-STDERR] {ctx}: promoted STRUCTURE->TABLE for "
                f"{fixed} (type_desc preserved: "
                f"{[getattr(p, 'type_desc', None) is not None for p in desc.parameters if p.name in fixed]})\n")
            _sys.stderr.flush()
        return desc

    # Patch AsyncConnection._call_bootstrap (the async path used by classic TCP)
    _AsyncConn = _conn_mod.AsyncConnection
    _orig_async_bootstrap = _AsyncConn._call_bootstrap

    async def _patched_async_bootstrap(self, func_name):
        desc = await _orig_async_bootstrap(self, func_name)
        return _fix_table_rfctype_post(desc, f"async_bootstrap({func_name})")

    _AsyncConn._call_bootstrap = _patched_async_bootstrap

    # Patch Connection._call_bootstrap (the sync path used by WS/SNC)
    _SyncConn = _conn_mod.Connection
    _orig_sync_bootstrap = _SyncConn._call_bootstrap

    def _patched_sync_bootstrap(self, func_name):
        desc = _orig_sync_bootstrap(self, func_name)
        return _fix_table_rfctype_post(desc, f"sync_bootstrap({func_name})")

    _SyncConn._call_bootstrap = _patched_sync_bootstrap

    _sys.stderr.write("[DBG-STDERR] saprfclib: _call_bootstrap patched on both Connection classes\n")
    _sys.stderr.flush()
    print("[DBG] saprfclib: _call_bootstrap patched (sync+async) — rfctype fix runs AFTER type_desc attach", flush=True)

    # -- Pad missing fields with type-appropriate defaults --

    def _default_for_field(child):
        rt = getattr(child, 'rfctype', 0)
        if rt in (8, 9, 10, 31):  # INT, INT2, INT1, INT8
            return 0
        if rt == 7:  # FLOAT
            return 0.0
        if rt in (4, 30):  # BYTE, XSTRING
            return b''
        return ''

    def _pad_row(row, type_desc):
        if type_desc is None:
            return row
        padded = None
        for child in type_desc.fields:
            if child.name not in row:
                if padded is None:
                    padded = dict(row)
                padded[child.name] = _default_for_field(child)
        return padded if padded is not None else row

    # -- Encode patch: pad missing fields + TABLE fallback --

    def _patched_encode(rfctype, value, field):
        td = getattr(field, 'type_desc', None)
        if isinstance(value, list) and rfctype in (5, 17):
            try:
                field.rfctype = 5
            except (AttributeError, TypeError):
                pass
            if td is not None:
                value = [_pad_row(r, td) for r in value]
            return _codec._encode_table(value, field)
        if isinstance(value, dict) and td is not None:
            value = _pad_row(value, td)
        return _original_encode(rfctype, value, field)

    # -- Decode patch: TABLE direction fallback --

    def _patched_decode(rfctype, value, field):
        if _is_table_direction(getattr(field, 'direction', '')):
            if rfctype != 5:
                try:
                    field.rfctype = 5
                except (AttributeError, TypeError):
                    pass
                return _codec._decode_table(value, field)
        return _original_decode(rfctype, value, field)

    _codec.encode = _patched_encode
    _codec.decode = _patched_decode
    if hasattr(_invoke, 'encode'):
        _invoke.encode = _patched_encode
    if hasattr(_invoke, 'decode'):
        _invoke.decode = _patched_decode

    logger.debug('saprfclib codec patched for TABLE param dispatch + '
                  'field padding')
except Exception as _patch_err:
    import traceback as _tb2
    _tb_str = _tb2.format_exc()
    _sys.stderr.write(f"[DBG-STDERR] saprfclib: monkey-patch FAILED: {_patch_err}\n{_tb_str}\n")
    _sys.stderr.flush()
    print(f"[DBG] saprfclib: monkey-patch FAILED: {_patch_err}", flush=True)
    logger.warning('saprfclib codec patch failed: %s', _patch_err)

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
        kwargs[attr] = getattr(exc, attr, '')

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
# Direction constant mapping for _make_func_desc
# ---------------------------------------------------------------------------

_DIR_MAP = {
    RFC_IMPORT:   'RFC_IMPORT',
    RFC_EXPORT:   'RFC_EXPORT',
    RFC_CHANGING: 'RFC_CHANGING',
    RFC_TABLES:   'RFC_TABLES',
}


# ---------------------------------------------------------------------------
# RFCTYPE int → saprfclib type-name mapping
# ---------------------------------------------------------------------------

_RFCTYPE_NAME = {
    0:  'RFCTYPE_CHAR',
    1:  'RFCTYPE_DATE',
    2:  'RFCTYPE_BCD',
    3:  'RFCTYPE_TIME',
    4:  'RFCTYPE_BYTE',
    5:  'RFCTYPE_TABLE',
    6:  'RFCTYPE_NUM',
    7:  'RFCTYPE_FLOAT',
    8:  'RFCTYPE_INT',
    9:  'RFCTYPE_INT2',
    10: 'RFCTYPE_INT1',
    14: 'RFCTYPE_NULL',
    17: 'RFCTYPE_STRUCTURE',
    23: 'RFCTYPE_DECF16',
    24: 'RFCTYPE_DECF34',
    29: 'RFCTYPE_STRING',
    30: 'RFCTYPE_XSTRING',
    31: 'RFCTYPE_INT8',
    32: 'RFCTYPE_UTCLONG',
}


# ---------------------------------------------------------------------------
# Discover which params saprfclib.connect() actually accepts (varies by
# version) so we can silently drop unsupported ones like 'lang'.
# ---------------------------------------------------------------------------

import inspect as _inspect

_SAPRFCLIB_PARAMS = frozenset(
    _inspect.signature(_lib.connect).parameters.keys()
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
        # saprfclib expects sysnr as int
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
            return self._conn.ping()
        except Exception:
            return False

    def ping(self):
        if self._conn is None:
            return False
        try:
            return self._conn.ping()
        except (ValueError, struct_error):
            # saprfclib got a response but couldn't parse it — the
            # connection IS alive, just a parser mismatch with this
            # kernel's RFCPING reply format.
            logger.debug('saprfclib ping() parse error (connection alive)')
            return True
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
        except (ValueError, struct_error):
            # Response received but unparseable — connection IS alive
            return (True, "", "")
        except _lib.AbapApplicationError as e:
            key = getattr(e, 'key', '')
            return (False, key, str(e))
        except _lib.SapRfcError as e:
            key = getattr(e, 'key', '')
            return (False, key, str(e))
        except Exception as e:
            return (False, type(e).__name__, str(e))

    def get_attributes(self):
        self._ensure_open()
        try:
            attrs = self._conn.get_connection_attributes()
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e
        if isinstance(attrs, dict):
            return attrs
        result = {}
        for field in ('dest', 'host', 'partnerHost', 'sysNumber',
                      'sysId', 'client', 'user', 'language',
                      'trace', 'isoLanguage', 'codepage',
                      'partnerCodepage', 'rfcRole', 'type',
                      'partnerType', 'rel', 'partnerRel',
                      'kernelRel', 'cpicConvId', 'progName',
                      'partnerBytesPerChar', 'partnerSystemCodepage',
                      'partnerIP', 'partnerIPv6'):
            val = getattr(attrs, field, None)
            if val is not None and str(val).strip():
                result[field] = str(val).strip()
        return result

    # -- RFC Function Invocation --

    def call(self, func_name, **kwargs):
        self._ensure_open()
        try:
            result = self._conn.call(func_name, **kwargs)
            return _normalize_result(result)
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e
        except Exception as e:
            tb_str = _tb.format_exc()
            print(f"[!] saprfclib call({func_name}) internal error:\n"
                  f"    {type(e).__name__}: {e}\n"
                  f"    --- saprfclib traceback ---\n{tb_str}"
                  f"    --------------------------")
            raise RFCError(f"saprfclib call({func_name}) failed: {e}") from e

    def _make_type_desc(self, name, fields):
        """Create a type description manually.

        Args:
            name: type name (e.g. "TAB200")
            fields: list of (field_name, rfctype, nuc_length, uc_length)
        """
        field_descs = []
        for fname, ftype, nuc_len, uc_len in fields:
            fd = _FieldDesc(
                name=fname,
                field_type=_RFCTYPE_NAME.get(ftype, 'RFCTYPE_CHAR'),
                nuc_length=nuc_len,
                uc_length=uc_len,
                nuc_offset=0,
                uc_offset=0,
                decimals=0,
            )
            field_descs.append(fd)
        return _TypeDesc(name=name, fields=field_descs)

    def _make_func_desc(self, func_name, params):
        """Create a function description manually.

        Args:
            func_name: FM name
            params: list of (name, direction, rfctype, uc_length,
                    nuc_length, type_desc_handle) tuples
        """
        param_descs = []
        for pname, direction, ptype, uc_len, nuc_len, td_handle in params:
            dir_str = _DIR_MAP.get(direction, 'RFC_IMPORT')
            type_str = _RFCTYPE_NAME.get(ptype, 'RFCTYPE_CHAR')
            fd = _FieldDesc(
                name=pname,
                field_type=type_str,
                nuc_length=nuc_len,
                uc_length=uc_len,
                nuc_offset=0,
                uc_offset=0,
                decimals=0,
                direction=dir_str,
                type_desc=td_handle,
            )
            param_descs.append(fd)
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
            print(f"[!] saprfclib call_raw({func_name}) internal error:\n"
                  f"    {type(e).__name__}: {e}\n"
                  f"    --- saprfclib traceback ---\n{tb_str}"
                  f"    --------------------------")
            raise RFCError(
                f"saprfclib call_raw({func_name}) failed: {e}") from e

    # -- Internal --

    def _ensure_open(self):
        if self._conn is None:
            raise RFCError("Connection is not open — call open() first")
