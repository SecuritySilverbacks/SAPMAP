"""Tests for issue #87 — SCC credentials must not be exposed in the UI.

The SCC (SAP Cloud Connector) node type used to leak the stored admin
password in two places of the single-page UI (`modules/core/sapmap_html.py`):

  1. the SCC context menu printed the stored password as clear text
     (`showSCCCtxMenu`), unlike every other node type which shows only the
     username; and
  2. the authenticated actions `sccPullMappings` / `sccExtractKeystore`
     ALWAYS re-prompted via plaintext browser `prompt()` dialogs pre-filled
     with the stored plaintext password — re-exposing it on every call.

The fix (client-only) mirrors the regular-node menu (username + a verified
mark, no password) and reuses the stored credential pair behind a
confirm-without-password dialog, falling back to the already-masked
`scc-cred-modal` when no credential is stored — never a plaintext prompt.

These are source-level guards on the JS bundled inside `get_html()`, the
same style as tests/test_pwspray_gui_multi_sid.py / tests/test_windows_lpe.py.
tests/test_rendered_js.py separately guards that the bundle still parses.
"""
from __future__ import annotations

import re

import pytest

import modules  # noqa: F401 — registers package paths


@pytest.fixture(scope="module")
def html() -> str:
    import sapmap_html
    return sapmap_html.get_html()


def _fn_body(html: str, name: str) -> str:
    """Return the source of a top-level JS function `name`, from its
    declaration up to (but not including) the next top-level function."""
    m = re.search(r"(?:async\s+)?function\s+" + re.escape(name) + r"\s*\(", html)
    assert m, f"{name} not found in bundled JS"
    start = m.start()
    nxt = re.search(r"\n(?:async\s+)?function\s+\w+\s*\(", html[start + 1:])
    end = start + 1 + nxt.start() if nxt else len(html)
    return html[start:end]


# ---------------------------------------------------------------------------
# Part 1 — SCC context menu must not render the password
# ---------------------------------------------------------------------------

def test_scc_context_menu_omits_password(html):
    body = _fn_body(html, "showSCCCtxMenu")
    # the exact leaking expression (stored password appended to the line)
    assert "' / ' + escHtml(p)" not in body, "SCC menu still appends the password"
    # the password field must not be referenced in the menu builder at all
    assert "c.password" not in body, "SCC menu still reads c.password"


def test_scc_context_menu_uses_verified_mark(html):
    body = _fn_body(html, "showSCCCtxMenu")
    # mirror the regular-node menu: mark derived from the real verified flag
    assert "c.verified ?" in body, "SCC menu should derive its mark from c.verified"


def test_no_plaintext_password_prompt_anywhere(html):
    # both sccPullMappings and sccExtractKeystore used this; it must be gone
    assert "prompt('Password for '" not in html, "a plaintext password prompt remains"
    # extract's backup-password prompt must no longer default to the stored pw
    assert "p || defPass" not in html, "backup prompt still defaults to the stored password"


# ---------------------------------------------------------------------------
# Part 2 — authenticated actions reuse stored creds / fall back to the modal
# ---------------------------------------------------------------------------

def _confirm_arg(body: str) -> str:
    """The text of the `if (!confirm(...)) return;` guard's argument."""
    m = re.search(r"confirm\((.*?)\)\)\s*return", body, re.S)
    assert m, "expected an `if (!confirm(...)) return;` guard"
    return m.group(1)


def test_pull_mappings_reuses_stored_creds(html):
    body = _fn_body(html, "sccPullMappings")
    assert "prompt('" not in body, "Pull Mappings still prompts in plaintext"
    assert "showSCCCredModal(host)" in body, "no masked-modal fallback when creds absent"
    assert "_sccStoredCreds(host)" in body
    # the reuse confirm must name the username but NEVER the password — guard
    # the new dialog surface this change introduced (the old test only proved
    # stored.username appeared *somewhere*, which the `p = stored.password`
    # assignment satisfied vacuously).
    arg = _confirm_arg(body)
    assert "stored.username" in arg, "the confirm should name the stored username"
    assert "password" not in arg.lower(), \
        "the Pull Mappings confirm dialog must not reference the password"


def test_extract_keystore_reuses_stored_creds(html):
    body = _fn_body(html, "sccExtractKeystore")
    # the admin username/password prompts are gone; only the (distinct)
    # backup passphrase prompt remains, and it no longer defaults to the pw
    assert "prompt('SCC admin username" not in body
    assert "prompt('Password for '" not in body
    assert body.count("prompt('") == 1, "only the backup-passphrase prompt should remain"
    assert "'Backup encryption password" in body
    assert "p || defPass" not in body
    assert "showSCCCredModal(host)" in body, "no masked-modal fallback when creds absent"
    # the credNote shown in the confirm names the username, never the password.
    # Slice only the two string branches (after `?`) so the boolean guard
    # `(stored && stored.username && stored.password)` — where stored.password
    # legitimately appears — is excluded.
    cn = re.search(r"const credNote =\s*\([^)]*\)\s*\?(.*?);", body, re.S)
    assert cn, "sccExtractKeystore should build a credNote"
    branches = cn.group(1)
    assert "stored.username" in branches, "the cred note should name the stored username"
    assert "password" not in branches.lower(), \
        "the cred note must not reference the password"
    assert "password" not in _confirm_arg(body).lower(), \
        "the extract confirm dialog must not reference the password"


def test_scc_cred_modal_is_masked(html):
    # the fallback modal's password field stays type=password (masked)
    assert re.search(r'id="scc-cred-pass"[^>]*type="password"', html) \
        or re.search(r'type="password"[^>]*id="scc-cred-pass"', html), \
        "scc-cred-pass must be a masked password input"
