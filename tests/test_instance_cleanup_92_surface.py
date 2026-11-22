#!/usr/bin/env python3
"""Issue #92 — source / HTML contract pins for the inline instance-cleanup
surface.

The Bottle route closures live inside ``create_app``'s scope and the
inline 'x' control is browser-side JS, so — per the project convention
(see tests/test_wd_set_type_rediscover.py and test_defense_rings_gui.py)
— these pin the WIRING in the served Python + HTML rather than invoking
it live.  The behavioural logic (suppress / unsuppress / prune / port
reconciliation / add_node carry-forward / producer gates) is unit-tested
in tests/test_instance_cleanup_92.py; JS validity is covered by
tests/test_rendered_js.py.  Their job here is to fail loudly if a
refactor silently drops a route, a producer gate, or the UI control.
"""
import inspect

import pytest

import modules  # noqa: F401 — registers package paths

import sapmap_gui
import sapmap_autopwn
import sapmap_scanner
import sapmap_html


@pytest.fixture(scope="module")
def gui_src():
    return inspect.getsource(sapmap_gui)


@pytest.fixture(scope="module")
def html():
    return sapmap_html.get_html()


def _route_body(src, handler):
    """Slice a route handler body: from its ``def`` to the next
    ``@app.route`` boundary."""
    start = src.find("def " + handler + "(")
    assert start != -1, "handler %s not found" % handler
    nxt = src.find("\n    @app.route", start)
    return src[start:(nxt if nxt != -1 else start + 2000)]


def _js_fn(html, name):
    start = html.find("function " + name + "(")
    assert start != -1, "JS function %s not found" % name
    nxt = html.find("\nfunction ", start + 1)
    return html[start:(nxt if nxt != -1 else start + 2000)]


# ---------------------------------------------------------------------------
# Backend route wiring
# ---------------------------------------------------------------------------

class TestRoutes:

    def test_remove_instance_route_defined(self, gui_src):
        assert '/api/node/<sid>/remove_instance' in gui_src
        assert "def node_remove_instance(sid):" in gui_src

    def test_remove_instance_delegates_to_model(self, gui_src):
        body = _route_body(gui_src, "node_remove_instance")
        assert "api.state.get_node(sid)" in body
        assert "node.suppress_instance(instance_nr)" in body
        assert '"remaining"' in body
        assert '"suppressed"' in body

    def test_unsuppress_route_defined(self, gui_src):
        assert '/api/node/<sid>/unsuppress_instance' in gui_src
        body = _route_body(gui_src, "node_unsuppress_instance")
        assert "node.unsuppress_instance(instance_nr)" in body

    def test_set_instance_nr_lifts_suppression(self, gui_src):
        body = _route_body(gui_src, "node_set_instance_nr")
        assert "node.unsuppress_instance(new_nr)" in body

    def test_remove_instance_validates_format(self, gui_src):
        # Review #3 — crafted instance_nr must be rejected (stored-XSS vector)
        body = _route_body(gui_src, "node_remove_instance")
        assert "instance_nr.isalnum()" in body
        assert "len(instance_nr) <= 4" in body


# ---------------------------------------------------------------------------
# Producer gates are wired (every re-add vector consults suppression)
# ---------------------------------------------------------------------------

class TestProducerGates:

    def test_gui_gates_present(self, gui_src):
        # _merge_scan_into_existing (fast rescan)
        assert "existing.is_instance_suppressed(si.instance_nr)" in gui_src
        # _correct_node_from_http (HTTP-probe overwrite)
        assert "target_node.is_instance_suppressed(probed)" in gui_src
        # _import_appserver_instances (MS fan-out append)
        assert "node.is_instance_suppressed(inst_nr)" in gui_src
        # retrieve_rfcs SAPControl backfill
        assert "_tgt_node.is_instance_suppressed(" in gui_src
        # /api/node/add gateway sweep
        assert 'node.is_instance_suppressed(\n' in gui_src or \
               "node.is_instance_suppressed(f" in gui_src

    def test_autopwn_gates_present(self):
        src = inspect.getsource(sapmap_autopwn)
        assert "target_node.is_instance_suppressed(probed)" in src   # _correct_node_http
        assert "tgt.is_instance_suppressed(real_inst)" in src        # SAPControl pivot

    def test_scanner_gates_present(self):
        src = inspect.getsource(sapmap_scanner)
        assert "node.is_instance_suppressed(inst_str)" in src        # _record_instance_port
        assert "node.prune_suppressed_instances()" in src            # deep-rescan prune
        assert "node.reconcile_vuln_flags()" in src                  # Review #5 deep-rescan re-light

    def test_exploit_and_secstore_gates_present(self):
        # Review #1 + safeguard-blocked finding — two more instance producers
        import sapmap_exploit
        import sap_java_secstore_runner
        assert "node.is_instance_suppressed(instance_nr)" in \
            inspect.getsource(sapmap_exploit)                         # _mark_java_http_port
        assert "down.is_instance_suppressed(tgt_sysnr)" in \
            inspect.getsource(sap_java_secstore_runner)               # auto-plot elif


# ---------------------------------------------------------------------------
# Frontend contract (System Details inline control)
# ---------------------------------------------------------------------------

class TestFrontend:

    def test_handlers_defined(self, html):
        assert "async function removeInstance(sid, instNr)" in html
        assert "async function restoreInstance(sid, instNr)" in html

    def test_inline_control_wired(self, html):
        # the row's 'x' lives in the showDetails template and calls removeInstance
        assert 'class="detail-del-btn"' in html
        # Review #3 — the instance_nr onclick arg is sanitized with instKey
        # (not escHtml, which leaves the single quote unescaped)
        assert "onclick=\"removeInstance('${escHtml(n.sid)}','${instKey(i.instance_nr)}')\"" in html
        assert "function instKey(" in html
        assert ".detail-del-btn {" in html   # destructive CSS present

    def test_remove_handler_route_and_confirm(self, html):
        body = _js_fn(html, "removeInstance")
        assert "node/${sid}/remove_instance" in body
        # conditional confirm — only last-instance or GW-bearing nags
        assert "insts.length <= 1" in body                 # isLast
        assert "p >= 3300 && p <= 3399" in body            # hasGw (gateway family)
        assert "confirm(msg)" in body
        assert "startPolling()" in body

    def test_restore_handler_route(self, html):
        body = _js_fn(html, "restoreInstance")
        assert "node/${sid}/unsuppress_instance" in body
        # Issue #92 (restore) — row is re-added instantly now; the old
        # "next scan repopulates it" copy must not linger (it was wrong).
        assert "next scan repopulates" not in body

    def test_suppressed_and_empty_rows_rendered(self, html):
        assert "suppressed_instance_nrs" in html                     # restore line
        assert "onclick=\"restoreInstance(" in html
        assert "No instances — host-level actions" in html           # empty-state note
