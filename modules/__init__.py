"""SAPMAP modules package.

Adds each topical subdirectory to ``sys.path`` so existing flat imports
(``import sapmap_models``, ``from sap_rfc_ctypes import ...``) keep
working after the file reorganisation.  Importing this package once at
process start (done from ``sapmap.py`` and ``tests/conftest.py``) is
enough — every SAPMAP module afterwards can import its peers by their
bare module name regardless of which subdirectory they live in.
"""
import os as _os
import sys as _sys

_HERE = _os.path.dirname(_os.path.abspath(__file__))
for _sub in ("core", "automation", "protocols", "discovery",
             "exploitation", "postex", "data_extraction",
             "business_impact", "ops"):
    _p = _os.path.join(_HERE, _sub)
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
