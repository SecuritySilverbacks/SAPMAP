#!/usr/bin/env python3
"""
SAPMAP — SAP Landscape Attack Path Mapper

Main entry point. Launches the SAPMAP GUI (Bottle HTTP server + pywebview).

Like BloodHound for Active Directory, but for SAP: discovers SAP systems,
maps RFC connections, exploits gateway vulnerabilities and weak configurations
to chart lateral movement paths across the entire SAP landscape.

Usage:
  python3 sapmap.py                          # Launch GUI
  python3 sapmap.py --load state.sapmap      # Load a saved state
  python3 sapmap.py --sdk /opt/nwrfcsdk/lib  # Set NW RFC SDK path
  python3 sapmap.py --no-gui --targets 10.0.0.0/24  # CLI-only scan

Requirements:
  - Python 3.8+
  - bottle (pip install bottle)
  - pywebview (pip install pywebview) — optional, falls back to browser

For authorized security testing only.
"""

import argparse
import logging
import os
import socket
import sys
import threading
import webbrowser
from datetime import datetime

# Ensure SAPMAP directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Register the modules/* subpackages on sys.path so the existing flat
# imports (`import sapmap_models`, `from sap_rfc_ctypes import ...`)
# keep working after the file reorganisation.  Importing the modules
# package once is enough — its __init__.py adds every subdir.
import modules  # noqa: F401

from sapmap_gui import SAPMAPApi, OutputCapture, create_app
from sapmap_state import (load_state, save_state, auto_save_path,
                          load_rfc_cache_into, load_created_destinations_into)
import sapmap_rfc


BANNER = r"""
   _____ ___    ____  __  ______    ____
  / ___//   |  / __ \/  |/  /   |  / __ \
  \__ \/ /| | / /_/ / /|_/ / /| | / /_/ /
 ___/ / ___ |/ ____/ /  / / ___ |/ ____/
/____/_/  |_/_/   /_/  /_/_/  |_/_/

  SAP Landscape Attack Path Mapper
  For authorized security testing only.
"""


def find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _resolve_sdk_path(cli_arg: str | None) -> tuple[str, str]:
    """Decide which NW RFC SDK path to activate at startup.

    Resolution order (first non-empty wins):

      1. ``--sdk`` on the CLI (explicit operator override for this run)
      2. ``nwrfcsdk_path`` in ``settings.local.json`` (set via
         Actions → Set NW RFC SDK Path in the GUI, persisted
         CWD-relative and gitignored)
      3. Nothing set — return ``("", "")`` and let the caller fall
         back to system ``LD_LIBRARY_PATH`` / ``DYLD_LIBRARY_PATH``.

    Returns ``(sdk_path, source_label)`` — source is used in the
    ``[*] NW RFC SDK path: ... (source: ...)`` log line so the
    operator can tell why the value they see was picked.

    Kept as a module-level helper (not inlined in ``main()``) so the
    resolution can be unit-tested with a tmp settings file.
    """
    if cli_arg:
        return cli_arg, "--sdk"
    try:
        import json as _json
        with open("settings.local.json") as _f:
            stored = _json.load(_f).get("nwrfcsdk_path", "")
            if stored:
                return stored, "settings.local.json"
    except Exception:
        pass
    return "", ""


def _resolve_sapology_path(cli_arg: str | None) -> tuple[str, str]:
    """Decide which SAPology directory to activate at startup.

    Resolution order (first non-empty wins):

      1. ``--sapology`` on the CLI (explicit operator override).
      2. ``$SAPMAP_SAPOLOGY_PATH`` environment variable — useful
         inside Docker where a bind mount lands the SAPology tree
         at a fixed target path.
      3. ``sapology_path`` in ``settings.local.json`` (set via the
         GUI settings modal).
      4. Nothing set — return ``("", "")`` and let
         ``sapmap_scanner`` fall back to its default sibling
         directory (``../SAPology`` relative to the SAPMAP root).

    Returns ``(sapology_path, source_label)`` so main() can print
    ``[*] SAPology path: ... (source: ...)``.
    """
    if cli_arg:
        return cli_arg, "--sapology"
    env = os.environ.get("SAPMAP_SAPOLOGY_PATH")
    if env:
        return env, "SAPMAP_SAPOLOGY_PATH env"
    try:
        import json as _json
        with open("settings.local.json") as _f:
            stored = _json.load(_f).get("sapology_path", "")
            if stored:
                return stored, "settings.local.json"
    except Exception:
        pass
    return "", ""


def main():
    parser = argparse.ArgumentParser(
        description="SAPMAP — SAP Landscape Attack Path Mapper"
    )
    parser.add_argument("--load", metavar="FILE",
                        help="Load a saved .sapmap state file")
    parser.add_argument("--sdk", metavar="PATH",
                        help="Path to SAP NW RFC SDK lib directory")
    parser.add_argument("--sapology", metavar="PATH",
                        help="Path to the SAPology checkout used for Deep "
                             "Scan.  Defaults to a sibling directory of "
                             "the SAPMAP root (../SAPology).  Also "
                             "configurable via $SAPMAP_SAPOLOGY_PATH or "
                             "'sapology_path' in settings.local.json.")
    parser.add_argument("--port", type=int, default=0,
                        help="HTTP server port (0=auto)")
    parser.add_argument("--host", metavar="ADDR",
                        default="127.0.0.1",
                        help="HTTP server bind address (default: 127.0.0.1). "
                             "Set to 0.0.0.0 when running inside a Docker "
                             "container with bridge networking so the GUI "
                             "is reachable from the host — see the Docker "
                             "section of README.md.  Binding to 0.0.0.0 on "
                             "a bare host exposes SAPMAP to the LAN and is "
                             "NOT recommended.")
    parser.add_argument("--browser", action="store_true",
                        help="Force browser mode (skip pywebview)")
    parser.add_argument("--no-gui", action="store_true",
                        help="Run without any GUI (server only, open browser manually)")
    parser.add_argument("--targets", metavar="TARGETS",
                        help="Scan targets (CLI mode, implies --no-gui)")
    parser.add_argument("--fast", action="store_true", default=True,
                        help="Fast scan mode (default)")
    parser.add_argument("--deep", action="store_true",
                        help="Deep scan mode (full SAPology)")
    parser.add_argument("--script", metavar="FILE",
                        help="Run a scripted scenario (YAML/JSON) with GUI visualization")
    parser.add_argument("--confirm", action="store_true",
                        help="Allow a --script run to execute destructive "
                             "actions (exploit_cve_31324, create_user_java). "
                             "Without this flag, those steps are skipped so "
                             "the playbook can be dry-run safely.")
    parser.add_argument("--step-delay", type=float, metavar="SECONDS",
                        help="Override the inter-step delay for --script runs "
                             "(default: 2s, or whatever the script's "
                             "top-level `step_delay` sets). Use 0 to disable.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--mcp", action="store_true",
                        help="Launch a Model Context Protocol (MCP) server "
                             "alongside the GUI.  The MCP server exposes "
                             "SAPMAP's capabilities as MCP tools over stdio "
                             "transport, allowing LLM agents (Claude, etc.) "
                             "to drive SAPMAP programmatically.  Connects "
                             "to the same HTTP server as the GUI.")
    parser.add_argument("--pure-rfc", action="store_true",
                        help="Use pure-Python RFC backend (saprfclib) "
                             "instead of the SAP NW RFC SDK.  Requires "
                             "Python 3.12+ and saprfclib installed.  "
                             "Falls back to the C SDK if unavailable.")
    parser.add_argument("--allow-evasion", action="store_true",
                        help="Arm Tier 3 active-evasion techniques "
                             "(SAL filter narrow, kernel-param dynamic-set, "
                             "STAD silencing, DBTABLOG suppression, NWA "
                             "log-config flip, ICM trace flip).  Without "
                             "this flag, every Tier 3 entry point refuses "
                             "with EvasionGateError.  Prints a banner at "
                             "startup detailing what's now available.  "
                             "Requires explicit written authorization for "
                             "active-evasion testing against in-scope "
                             "targets.")

    args = parser.parse_args()

    # Logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    sdk_path, sdk_source = _resolve_sdk_path(args.sdk)
    if sdk_path:
        sapmap_rfc.set_sdk_path(sdk_path)
        print(f"[*] NW RFC SDK path: {sdk_path} (source: {sdk_source})")

    if getattr(args, "pure_rfc", False):
        sapmap_rfc.set_pure_rfc(True)
        print("[*] Pure-Python RFC backend requested (--pure-rfc)")

    sapology_path, sapology_source = _resolve_sapology_path(args.sapology)
    if sapology_path:
        from sapmap_scanner import set_sapology_path as _set_sapology
        _set_sapology(sapology_path)
        print(f"[*] SAPology path: {sapology_path} "
              f"(source: {sapology_source})")

    # Create API controller
    api = SAPMAPApi()

    # Load saved state if specified
    if args.load:
        try:
            api.state = load_state(args.load)
        except Exception as e:
            print(f"[-] Could not load state: {e}")
            sys.exit(1)
    else:
        # Load persistent RFC cache and created destinations
        load_rfc_cache_into(api.state)
        load_created_destinations_into(api.state)

    # Persist the --allow-evasion CLI choice onto the session state so
    # every Tier 3 gate check sees it.  We OR with whatever the loaded
    # .sapmap session already had, so loading a state file that was
    # saved with the flag on keeps it on across restarts; passing
    # --allow-evasion can only raise the arm level, never lower it.
    if getattr(args, "allow_evasion", False):
        try:
            evasion = dict(api.state.evasion or {})
            evasion["allow_evasion"] = True
            api.state.evasion = evasion
        except Exception as e:
            print(f"[!] Could not persist --allow-evasion: {e}")

    # CLI-only scan mode
    if args.targets:
        args.no_gui = True
        _cli_scan(api, args)
        return

    # Redirect stdout FIRST so the banners land in both the real
    # terminal AND the GUI console.  Earlier code printed the
    # banners before OutputCapture to work around a "banner
    # duplicated 80x" report — but that pushed the disclaimer
    # off the GUI entirely, which was worse than the original
    # bug.  ``print_evasion_banner()`` still carries an internal
    # ``_banner_emitted`` idempotent guard, and ``main()`` runs
    # exactly once per process, so neither print here can fire
    # more than once anyway.
    sys.stdout = OutputCapture(sys.__stdout__)

    # Disclaimer banner — first thing an operator sees in the GUI
    # console.  SAPMAP ships real working SAP exploits; make the
    # intended-use boundaries impossible to miss on the way in.
    banner = (
        "\n"
        "================================================================\n"
        "                ⚡  SAPMAP — DISCLAIMER ⚡\n"
        "================================================================\n"
        "  Use at your own risk.  SAPMAP implements real, working\n"
        "  exploits against SAP NetWeaver systems.  Running it against\n"
        "  a system you do not own or do not have explicit written\n"
        "  permission to test is ILLEGAL in most jurisdictions.\n"
        "\n"
        "  Intended uses:\n"
        "    • authorized penetration tests / red-team engagements\n"
        "    • defensive research on systems you own or administer\n"
        "    • educational study of SAP attack surfaces\n"
        "    • SOC / blue-team detection-engineering exercises\n"
        "\n"
        "  The authors accept no liability for any damage caused by\n"
        "  the use or misuse of this tool.  Clean up artifacts\n"
        "  (Actions → Cleanup All Users) when you're done.\n"
        "================================================================\n"
    )
    print(banner)

    if getattr(args, "allow_evasion", False):
        try:
            from sapmap_evasion_gate import print_evasion_banner
            print_evasion_banner()
        except Exception as e:
            print(f"[!] Could not print evasion banner: {e}")

    # Create Bottle app
    app = create_app(api)

    # Find port
    port = args.port or find_free_port()
    url = f"http://127.0.0.1:{port}"

    print(f"[*] Starting SAPMAP server on {url}")

    # Start Bottle server in background thread (threaded so stop/poll don't block)
    from socketserver import ThreadingMixIn
    from wsgiref.simple_server import WSGIServer
    class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
        daemon_threads = True

    server_thread = threading.Thread(
        target=lambda: app.run(
            host=args.host, port=port, quiet=True,
            server_class=ThreadedWSGIServer,
        ),
        daemon=True,
    )
    server_thread.start()

    # Give server a moment to start
    import time
    time.sleep(0.5)

    # Launch script runner in background (if --script provided)
    if args.script:
        from sapmap_script import ScriptRunner
        runner = ScriptRunner(url, args.script, confirm=args.confirm,
                              step_delay=args.step_delay)
        try:
            runner.load()
        except Exception as e:
            print(f"[!] Failed to load script: {e}")
            return
        # Run script in a background thread so the GUI launches immediately
        script_thread = threading.Thread(
            target=lambda: runner.run(print_fn=print),
            daemon=True,
        )
        # Delay script start so the GUI has time to open and render
        def _delayed_script():
            time.sleep(3)
            runner.run(print_fn=print)
        script_thread = threading.Thread(target=_delayed_script, daemon=True)
        script_thread.start()

    # Launch MCP server (if --mcp)
    if args.mcp:
        try:
            from sapmap_mcp_server import _set_base_url, mcp as mcp_server
            _set_base_url(port)
            # MCP stdio transport needs the real stdin/stdout (with .buffer),
            # but OutputCapture has already replaced sys.stdout above.
            # Restore originals inside the MCP thread.
            _real_stdin = sys.__stdin__
            _real_stdout = sys.__stdout__
            def _run_mcp():
                sys.stdin = _real_stdin
                sys.stdout = _real_stdout
                mcp_server.run(transport="stdio")
            mcp_thread = threading.Thread(target=_run_mcp, daemon=True)
            mcp_thread.start()
            print(f"[*] MCP server started (stdio transport, "
                  f"backend → http://127.0.0.1:{port})")
        except ImportError:
            print("[!] MCP server unavailable — install the 'mcp' package: "
                  "pip install mcp")
        except Exception as e:
            print(f"[!] MCP server failed to start: {e}")

    # Launch GUI
    use_browser = args.browser or args.no_gui

    if not use_browser:
        use_browser = not _try_pywebview(url, args.debug)

    if use_browser:
        if not args.no_gui:
            print(f"[*] Opening {url} in your default browser...")
            webbrowser.open(url)
        else:
            print(f"[*] Server running at {url}")
        _wait_for_exit(api)

    # Auto-save on exit
    _auto_save_on_exit(api)


def _patch_pywebview_gtk():
    """Monkey-patch pywebview's GTK backend for WebKit2GTK 4.0 compatibility.

    Only relevant on Linux where pywebview uses GTK/WebKit2GTK.
    On macOS (WKWebView) and Windows (EdgeChromium) this is a no-op.

    pywebview >= 4.4 uses WebKit2GTK 4.1 APIs that don't exist in 4.0:
      - WebView.evaluate_javascript()  -> patched to use run_javascript()
      - WebView.evaluate_javascript_finish() -> patched to use run_javascript_finish()
      - NavigationAction.get_frame_name() -> patched to return ''

    This avoids the need to downgrade pywebview or upgrade the system's
    WebKit2GTK package.
    """
    import sys
    if sys.platform != 'linux':
        return False  # Only needed on Linux (GTK/WebKit2GTK)
    try:
        import gi
        gi.require_version('Gtk', '3.0')
        gi.require_version('WebKit2', '4.0')
        from gi.repository import WebKit2

        wv_test = WebKit2.WebView()
        needs_patch = not hasattr(wv_test, 'evaluate_javascript')
        if not needs_patch:
            return False  # No patching needed

        print("[*] Patching pywebview for WebKit2GTK 4.0 compatibility ...")

        # Patch 1: WebView.evaluate_javascript -> run_javascript
        #   evaluate_javascript(script, length, world_name, source_uri,
        #                       cancellable, callback)
        #   run_javascript(script, cancellable, callback)
        _orig_run_js = WebKit2.WebView.run_javascript
        _orig_run_js_finish = WebKit2.WebView.run_javascript_finish

        def _evaluate_javascript(self, script, length=-1, world_name=None,
                                 source_uri=None, cancellable=None, callback=None):
            if callback:
                return _orig_run_js(self, script, cancellable, callback)
            else:
                return _orig_run_js(self, script, cancellable, None)

        def _evaluate_javascript_finish(self, task):
            try:
                js_result = _orig_run_js_finish(self, task)
                return js_result.get_js_value() if js_result else None
            except Exception:
                return None

        WebKit2.WebView.evaluate_javascript = _evaluate_javascript
        WebKit2.WebView.evaluate_javascript_finish = _evaluate_javascript_finish

        # Patch 2: NavigationAction.get_frame_name -> always return ''
        #   get_frame_name() was removed in WebKit2GTK 4.0; the pywebview
        #   GTK backend uses it to detect _blank target links.
        na_class = getattr(WebKit2, 'NavigationAction', None)
        if na_class and not hasattr(na_class, 'get_frame_name'):
            na_class.get_frame_name = lambda self: ''

        print("[+] WebKit2GTK 4.0 patches applied successfully")
        return True

    except Exception as e:
        print(f"[!] Could not patch WebKit2GTK: {e}")
        return False


def _try_pywebview(url: str, debug: bool = False) -> bool:
    """Attempt to launch pywebview.  Returns True if it ran successfully."""
    try:
        import webview
    except ImportError:
        print("[!] pywebview not installed, using browser mode")
        return False

    # Apply compatibility patches for WebKit2GTK 4.0 if needed
    _patch_pywebview_gtk()

    try:
        print("[*] Launching pywebview window...")
        icons_dir = os.path.join(os.path.dirname(__file__), "icons")
        # Windows pywebview routes icon= through System.Drawing.Icon, which
        # only accepts .ico — a PNG here throws ArgumentException at startup.
        icon_name = "sapmap.ico" if sys.platform == "win32" else "sapmap_256x256.png"
        icon_path = os.path.abspath(os.path.join(icons_dir, icon_name))
        if not os.path.exists(icon_path):
            print(f"[!] Icon not found: {icon_path}")
            icon_path = None

        # Set platform-specific application icon.
        # pywebview's icon= param only works on GTK/QT, not macOS Cocoa.
        if icon_path and sys.platform != "darwin":
            # Linux: set GTK default icon + WM_CLASS for taskbar
            try:
                import gi
                gi.require_version("Gtk", "3.0")
                from gi.repository import Gtk, GLib
                GLib.set_prgname("sapmap")
                GLib.set_application_name("SAPMAP")
                Gtk.Window.set_default_icon_from_file(icon_path)
            except Exception:
                pass

        # macOS: set dock icon AFTER pywebview initializes NSApplication.
        # Use webview.start(func=) to run code after the Cocoa event loop starts.
        def _set_macos_icon():
            if sys.platform != "darwin" or not icon_path:
                return
            import time
            time.sleep(0.5)  # let Cocoa fully initialize
            try:
                import AppKit
                ns_image = AppKit.NSImage.alloc().initWithContentsOfFile_(icon_path)
                if ns_image:
                    AppKit.NSApplication.sharedApplication().setApplicationIconImage_(ns_image)
            except Exception:
                pass

        window = webview.create_window(
            "SAPMAP — SAP Landscape Attack Path Mapper",
            url,
            width=1400,
            height=900,
            min_size=(1000, 700),
        )
        start_func = _set_macos_icon if sys.platform == "darwin" else None
        webview.start(func=start_func, debug=debug, icon=icon_path)
        return True
    except Exception as e:
        print(f"[!] pywebview error: {e}")
        print("[*] Falling back to browser mode...")
        return False


def _wait_for_exit(api):
    """Wait for keyboard interrupt in browser/CLI mode."""
    try:
        print("[*] Press Ctrl+C to exit")
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")


def _auto_save_on_exit(api):
    """Auto-save state on exit if there's any data."""
    if api.state.nodes:
        try:
            filepath = auto_save_path()
            save_state(api.state, filepath)
            # Restore stdout for final message
            if hasattr(sys.stdout, 'original') and sys.stdout.original:
                sys.stdout = sys.stdout.original
            print(f"[*] Auto-saved state to {filepath}")
        except Exception as e:
            print(f"[!] Auto-save failed: {e}")


def _cli_scan(api, args):
    """Run a scan from the command line without GUI."""
    from sapmap_scanner import parse_targets, discover_systems

    targets = parse_targets(args.targets)
    if not targets:
        print("[-] No valid targets")
        sys.exit(1)

    fast_mode = not args.deep
    nodes = discover_systems(
        targets,
        fast_mode=fast_mode,
        verbose=args.verbose,
    )

    for node in nodes:
        api.state.add_node(node)

    # Print summary
    stats = api.state.stats()
    print(f"\n{'='*60}")
    print(f"  SAPMAP Scan Results")
    print(f"  Systems found:  {stats['systems']}")
    print(f"  Production:     {stats['production_systems']}")
    print(f"{'='*60}")

    for sid, node in api.state.nodes.items():
        print(f"\n  {sid} ({node.hostname or node.ip})")
        print(f"    Type: {node.system_type}  OS: {node.os_type}  DB: {node.db_type}")
        print(f"    Kernel: {node.kernel}  Clients: {len(node.clients)}")
        if node.findings:
            print(f"    Findings: {len(node.findings)}")
        if node.gw_vulnerable:
            print(f"    [!] Gateway VULNERABLE")

    # Save state
    filepath = auto_save_path()
    save_state(api.state, filepath)


if __name__ == "__main__":
    main()
