"""Pure-Python RFC backend — wraps saprfclib with the same interface as
sap_rfc_ctypes.RFCConnection so that every call site in SAPMAP works
unchanged.

saprfclib requires Python 3.12+.  On older interpreters this module
will fail to import, and SAPMAP falls back to the C SDK automatically.
"""

import logging

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
            return self._conn.call(func_name, **kwargs)
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e
        except Exception as e:
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
        """Call using a manually-built function description."""
        self._ensure_open()
        try:
            return self._conn.call(func_name, func_desc=func_desc, **kwargs)
        except _lib.SapRfcError as e:
            raise _translate_exception(e) from e

    # -- Internal --

    def _ensure_open(self):
        if self._conn is None:
            raise RFCError("Connection is not open — call open() first")
