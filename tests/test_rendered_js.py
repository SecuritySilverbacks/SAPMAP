#!/usr/bin/env python3
"""Smoke test: the JS bundled inside sapmap_html.py must parse.

The page renders a huge multi-thousand-line <script> block built up
across many Python f-strings.  It's easy to accidentally write a
JavaScript-invalid construct that looks fine in Python — most notably
the implicit string-concatenation Python does between adjacent string
literals:

    'check_ms': ('long hint text — '
                  'continued on the next line'),

That's valid Python and produces a single string, but in JavaScript
it's a SyntaxError that breaks the ENTIRE page's script bundle —
hence "the Start button does nothing" symptoms.

These tests catch the failure mode in two complementary ways:

  (a) `node --check` on the rendered <script> when node is available
      on the test host (will work in CI with a node-bearing image).
  (b) A regex sweep that catches the specific Python-implicit-concat
      pattern inside JS object-literal values, even when node isn't
      available.  Less precise but always runs.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile

import pytest


def _extract_scripts() -> list:
    """Pull every <script>...</script> body out of the rendered HTML."""
    import sapmap_html
    html = sapmap_html.get_html()
    return re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)


def test_rendered_js_parses_with_node_if_available():
    """Run `node --check` over every <script> block in the rendered
    page.  Skipped when node isn't installed (CI without a node-
    bearing image)."""
    if not shutil.which("node"):
        pytest.skip("node not available")
    scripts = _extract_scripts()
    assert scripts, "no <script> blocks found in rendered HTML"
    for i, s in enumerate(scripts):
        tf = tempfile.NamedTemporaryFile(suffix=".js", mode="w",
                                            delete=False)
        try:
            tf.write(s)
            tf.close()
            r = subprocess.run(["node", "--check", tf.name],
                                capture_output=True, text=True)
            assert r.returncode == 0, (
                f"<script> block {i} has a JS syntax error:\n"
                + (r.stderr or "<no stderr>")
            )
        finally:
            import os
            try: os.unlink(tf.name)
            except OSError: pass


# Pattern: an object-literal value that's an open-paren followed by a
# string literal, then a newline, then more whitespace, then ANOTHER
# string literal that isn't joined with `+`.  Catches Python's implicit
# string concat as bled into JS.
_PYTHON_STYLE_CONCAT_RE = re.compile(
    r"""
    :                              # object-key colon
    \s*\(                           # opening paren (wrapped value)
    \s*(?:'[^']*'|"[^"]*")          # first string literal
    \s*\n\s*                        # newline + indent
    (?:'[^']*'|"[^"]*")             # second string literal — NOT preceded by `+`
    """,
    re.VERBOSE,
)


def test_no_python_style_implicit_string_concat_in_js():
    """The hint/rule objects in sapmap_html.py are written as JS object
    literals — but they sit inside a Python f-string, so Python-style
    paren-wrapped multi-line string concat will SILENTLY pass the
    Python parser and corrupt the JS at render time.  Scan for the
    pattern explicitly so a regression surfaces in unit tests rather
    than in the GUI's Start button doing nothing."""
    scripts = _extract_scripts()
    for i, s in enumerate(scripts):
        m = _PYTHON_STYLE_CONCAT_RE.search(s)
        assert m is None, (
            f"<script> block {i} contains a Python-style implicit "
            f"string concat that is invalid JavaScript:\n\n"
            f"  ...{s[max(0, m.start() - 80):m.end() + 80]}...\n\n"
            f"Replace with explicit `+` between the strings, or "
            f"collapse to a single line."
        )
