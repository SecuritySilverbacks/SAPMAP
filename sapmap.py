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


def main():
    parser = argparse.ArgumentParser(
        description="SAPMAP — SAP Landscape Attack Path Mapper"
    )
    parser.add_argument("--load", metavar="FILE",
                        help="Load a saved .sapmap state file")
    parser.add_argument("--sdk", metavar="PATH",
                        help="Path to SAP NW RFC SDK lib directory")
    parser.add_argument("--port", type=int, default=0,
                        help="HTTP server port (0=auto)")
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
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    # Logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print(BANNER)

    # Set SDK path
    if args.sdk:
        sapmap_rfc.set_sdk_path(args.sdk)
        print(f"[*] NW RFC SDK path: {args.sdk}")

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

    # CLI-only scan mode
    if args.targets:
        args.no_gui = True
        _cli_scan(api, args)
        return

    # Redirect stdout to capture console output
    sys.stdout = OutputCapture(sys.__stdout__)

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
            host="127.0.0.1", port=port, quiet=True,
            server_class=ThreadedWSGIServer,
        ),
        daemon=True,
    )
    server_thread.start()

    # Give server a moment to start
    import time
    time.sleep(0.5)

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
        icon_path = os.path.join(os.path.dirname(__file__), "icons", "sapmap_256x256.png")
        window = webview.create_window(
            "SAPMAP — SAP Landscape Attack Path Mapper",
            url,
            width=1400,
            height=900,
            min_size=(1000, 700),
        )
        webview.start(debug=debug, icon=icon_path)
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
