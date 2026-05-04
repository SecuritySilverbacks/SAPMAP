"""Pytest auto-loaded fixture file.

Adds the SAPMAP project root to ``sys.path`` and imports the ``modules``
package so its __init__.py registers every modules/* subdirectory.
After this, the test files' existing flat imports
(``from sapmap_models import ...``) continue to work without per-file
modifications even though the source files now live in
``modules/<group>/``.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import modules  # noqa: F401, E402  — registers subdir paths
