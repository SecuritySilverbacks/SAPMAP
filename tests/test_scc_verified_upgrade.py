"""Tests for issue #145 — a successful SCC login must upgrade an existing
Set-Credentials entry to verified, not skip it.

`scc_set_credentials` stores a pair `verified=False`. A later successful
`pull_mappings` / `extract_keystore` login used an append-only guard
(`if not any(username matches): append(verified=True)`), so a pair already
present under the same username was never flipped to verified — working creds
kept showing as unverified in the UI. `_record_verified_scc_cred` now upgrades
the matching entry in place (verified + refreshed password), appending only
when none matches. Both SCC login paths route through the helper.
"""
from __future__ import annotations

import re

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_gui as G
from sapmap_models import SCCNode, Credentials


def _scc(creds=None):
    sn = SCCNode(host="scc.lab.local")
    sn.credentials = list(creds) if creds is not None else []
    return sn


# ---------------------------------------------------------------------------
# _record_verified_scc_cred — behaviour
# ---------------------------------------------------------------------------

def test_upgrades_existing_unverified_entry_in_place():
    """The issue's exact case: a Set-Credentials pair (verified=False) must flip
    to verified on a successful login — in place, not as a second row."""
    sn = _scc([Credentials(username="Administrator", password="old", verified=False)])
    G._record_verified_scc_cred(sn, "Administrator", "old")
    assert len(sn.credentials) == 1, "must not append a duplicate row"
    assert sn.credentials[0].verified is True
    assert sn.credentials[0].username == "Administrator"


def test_refreshes_password_on_upgrade():
    """If the login succeeded with a corrected password, store that one."""
    sn = _scc([Credentials(username="Administrator", password="stale", verified=False)])
    G._record_verified_scc_cred(sn, "Administrator", "correct")
    assert len(sn.credentials) == 1
    assert sn.credentials[0].password == "correct"
    assert sn.credentials[0].verified is True


def test_appends_when_username_differs():
    sn = _scc([Credentials(username="Administrator", password="a", verified=True)])
    G._record_verified_scc_cred(sn, "sccadmin", "b")
    assert [c.username for c in sn.credentials] == ["Administrator", "sccadmin"]
    assert sn.credentials[1].verified is True and sn.credentials[1].password == "b"
    # the untouched entry is preserved
    assert sn.credentials[0].password == "a" and sn.credentials[0].verified is True


def test_appends_when_empty():
    sn = _scc([])
    G._record_verified_scc_cred(sn, "Administrator", "pw")
    assert len(sn.credentials) == 1
    assert sn.credentials[0].verified is True and sn.credentials[0].password == "pw"


def test_non_fatal_when_credentials_none():
    """Defensive: a None list (not the dataclass default) must not raise."""
    sn = _scc([])
    sn.credentials = None
    G._record_verified_scc_cred(sn, "Administrator", "pw")
    assert sn.credentials and sn.credentials[0].verified is True


def test_upgrades_first_match_only():
    """Two entries share the username: only the FIRST is upgraded (the helper
    returns after it) and the second same-username row is left untouched — so a
    regression to 'upgrade every match' (which would also clobber the second
    row's password) is caught."""
    sn = _scc([
        Credentials(username="Administrator", password="old1", verified=False),
        Credentials(username="Administrator", password="old2", verified=False),
    ])
    G._record_verified_scc_cred(sn, "Administrator", "z")
    assert len(sn.credentials) == 2
    assert sn.credentials[0].verified is True and sn.credentials[0].password == "z"
    # the second same-username row must be untouched (not upgraded, not clobbered)
    assert sn.credentials[1].verified is False and sn.credentials[1].password == "old2"


def test_selective_match_leaves_other_usernames_untouched():
    sn = _scc([
        Credentials(username="Administrator", password="x", verified=False),
        Credentials(username="other", password="y", verified=False),
    ])
    G._record_verified_scc_cred(sn, "Administrator", "z")
    assert len(sn.credentials) == 2
    assert sn.credentials[0].verified is True and sn.credentials[0].password == "z"
    assert sn.credentials[1].verified is False and sn.credentials[1].password == "y"


# ---------------------------------------------------------------------------
# Both SCC login paths are wired to the helper (the append-only guard is gone)
# ---------------------------------------------------------------------------

def test_both_login_paths_use_the_helper():
    import inspect
    src = inspect.getsource(G)
    # both call sites (pull_mappings + extract_keystore) route to the helper.
    # The def's annotated signature (`sn, user: str, pwd: str`) does not match
    # this bare call string, so the count is exactly the two call sites.
    assert src.count("_record_verified_scc_cred(sn, user, pwd)") == 2
    # the old append-only guard must be gone from both sites
    assert 'already = any(getattr(c, "username", "") == user' not in src
    assert 'if not any(getattr(c, "username", "") == user' not in src
