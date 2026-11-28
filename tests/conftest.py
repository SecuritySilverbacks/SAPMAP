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
import tempfile

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import modules  # noqa: F401, E402  — registers subdir paths


# Issue #85 follow-up — isolate every test from the operator's real
# ``states/.sapmap_lock_whitelist.json``.  ``SAPMAPState.__post_init__`` /
# ``from_dict`` now auto-load that dotfile, so a developer who uses the
# new "Make permanent" checkbox on their own workstation would otherwise
# see tests like ``test_fresh_state_is_seeded`` fail on the extra
# patterns they themselves added.  The autouse fixture redirects
# ``LOCK_WHITELIST_FILE`` to a per-test tmpdir, giving every test a
# pristine empty-dotfile view regardless of the dev's actual config.
@pytest.fixture(autouse=True)
def _isolate_global_lock_whitelist(monkeypatch, tmp_path_factory):
    import sapmap_state  # noqa: E402 — modules are on sys.path by now
    tmp = tmp_path_factory.mktemp("lock-whitelist-isolation")
    monkeypatch.setattr(
        sapmap_state, "LOCK_WHITELIST_FILE",
        str(tmp / ".sapmap_lock_whitelist.json"))
    yield
