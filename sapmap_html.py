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
}
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
.activity-dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  background: #f0883e; margin-right: 6px; animation: pulse 1.2s ease-in-out infinite;
}
#activity-bar {
  display: none; align-items: center; gap: 6px;
  background: #1a1510; border-bottom: 1px solid #f0883e40;
  padding: 3px 12px; flex-shrink: 0; font-size: 11px; color: #f0883e;
}
#activity-bar.active { display: flex; }
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
      <div class="dd-item" onclick="cleanupAll()">&#129529; Cleanup All Users</div>
      <div class="dd-item" onclick="resetRFCCache()">&#128202; Reset RFC Check List</div>
      <div class="dd-item" onclick="viewRFCCache()">&#128203; View RFC Check List</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="showCreatedUsers()">&#128203; View Created Users</div>
      <div class="dd-item" onclick="showCreatedDestinations()">&#128203; View Created TCP/IP Destinations</div>
      <div class="dd-item" onclick="clearCreatedDestinations()">&#128465; Clear TCP/IP Destinations List</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="showAddSystemModal()">&#10133; Add System Manually</div>
      <div class="dd-item" onclick="showSetPasswordModal()">&#128273; Set Default Password</div>
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
</div>

<!-- Activity Bar -->
<div id="activity-bar"><span class="activity-dot"></span><span id="activity-text">Working...</span></div>

<!-- Main Area -->
<div class="main">
  <!-- Map -->
  <div class="map-container" id="map-container">
    <div class="empty-msg" id="empty-msg">Start a scan or load a saved state to discover SAP systems</div>
    <svg id="map-svg" xmlns="http://www.w3.org/2000/svg"></svg>
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
      <div class="ctx-item" data-action="rfc_system_info">&#128225; RFC System Info</div>
      <div class="ctx-item" data-action="check_gw">&#128270; Check GW Vulnerability</div>
      <div class="ctx-item" data-action="check_ms">&#128270; Check MS Betrusted (CVE-2020-6207)</div>
      <div class="ctx-item" data-action="check_cve_31324">&#128270; Check CVE-2025-31324 (Java VisualComposer)</div>
      <div class="ctx-item" data-action="check_cve_6287">&#128270; Check CVE-2020-6287 (RECON)</div>
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
  'CONTENT_SERVER': 'Content', 'SAPROUTER': 'Router', 'MDM': 'MDM',
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
  };
  // Reset console cursor so new scan output is visible
  consoleCursor = 0;
  document.getElementById('console-body').innerHTML = '';
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

  if (nodeKeys.length === 0) {
    document.getElementById('empty-msg').style.display = 'block';
    document.getElementById('legend-bar').style.display = 'none';
    document.getElementById('map-svg').innerHTML = '';
    return;
  }
  document.getElementById('empty-msg').style.display = 'none';
  document.getElementById('legend-bar').style.display = 'flex';

  const svg = document.getElementById('map-svg');
  const BOX_W = 240, BOX_H = 174, MARGIN = 60;
  const cols = Math.max(1, Math.min(4, nodeKeys.length));

  // Auto-layout (grid) for nodes without positions
  // Place new nodes in free space, avoiding overlap with existing nodes
  const placedBoxes = [];
  nodeKeys.forEach(sid => {
    const n = nodes[sid];
    if (n._x != null) placedBoxes.push({ x: n._x, y: n._y });
  });

  function overlapsAny(x, y) {
    for (const b of placedBoxes) {
      if (Math.abs(x - b.x) < BOX_W + MARGIN/2 && Math.abs(y - b.y) < BOX_H + MARGIN/2)
        return true;
    }
    return false;
  }

  nodeKeys.forEach((sid, idx) => {
    const n = nodes[sid];
    if (n._x == null) {
      // Try grid position first, then search for free slot
      let col = idx % cols, row = Math.floor(idx / cols);
      let px = MARGIN + col * (BOX_W + MARGIN);
      let py = MARGIN + row * (BOX_H + MARGIN);
      if (overlapsAny(px, py)) {
        // Scan grid slots until a free one is found
        let found = false;
        for (let r = 0; r < 100 && !found; r++) {
          for (let c = 0; c < cols && !found; c++) {
            px = MARGIN + c * (BOX_W + MARGIN);
            py = MARGIN + r * (BOX_H + MARGIN);
            if (!overlapsAny(px, py)) found = true;
          }
        }
      }
      n._x = px;
      n._y = py;
      placedBoxes.push({ x: px, y: py });
    }
  });

  // Compute content bounds (needed for initial auto-fit and fitMap)
  let maxX = 0, maxY = 0;
  nodeKeys.forEach(sid => {
    const n = nodes[sid];
    maxX = Math.max(maxX, (n._x || 0) + BOX_W + MARGIN);
    maxY = Math.max(maxY, (n._y || 0) + BOX_H + MARGIN);
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

  // Draw connections first (behind nodes)
  const newConnKeys = new Set();
  conns.forEach((conn, ci) => {
    const srcNode = nodes[conn.source_sid];
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
      `rx="6" fill="${fill}" stroke="${borderColor}" stroke-width="${borderWidth}" />`;

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

    // Lightning bolt for pwned
    if (n.pwned) {
      html += `<text x="${x+BOX_W-22}" y="${y+19}" font-size="16" fill="#f0883e">&#9889;</text>`;
    }

    // Activity spinner for active background tasks
    if (_nodeHasActiveTask(sid)) {
      const cx = n.pwned ? x+BOX_W-40 : x+BOX_W-18;
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
    // Draw glowing edges between consecutive nodes in the chain
    for (let i = 0; i < _highlightedChain.length - 1; i++) {
      const srcSid = _highlightedChain[i];
      const tgtSid = _highlightedChain[i + 1];
      const srcN = nodes[srcSid]; const tgtN = nodes[tgtSid];
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
      const nNode = nodes[nSid];
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
  if (firstRender) firstRender = false;

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
  selectedNodeSid = sid;
  const n = (mapState.nodes || {})[sid];
  const menu = document.getElementById('ctx-menu');

  // Determine node capabilities
  const hasCreds = n && ((n.credentials || []).length > 0 || (n.created_users || []).length > 0 || n.pwned);
  const hasGwVuln = n && n.gw_vulnerable;
  const hasMsVuln = n && n.ms_vulnerable;
  const hasMsPort = n && n.ms_port > 0;
  const sysType = (n && typeof n.system_type === 'string') ? n.system_type.toUpperCase() : '';
  const isJavaStack = sysType.indexOf('JAVA') !== -1;
  const isAbapStack = sysType.indexOf('ABAP') !== -1;
  const isSaprouter = sysType.indexOf('SAPROUTER') !== -1;
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
    'deep_scan':        true,                       // always available
    'retrieve_rfcs':    hasCreds,                   // need credentials/access
    'test_rfcs':        hasCreds && hasRFCs,        // need access + existing RFCs
    'read_java_destinations': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy),
    // ABAP path uses RFC BAPIs (SAP_ALL user or gateway); Java path
    // needs a JSP-deploy primitive. A RECON UME user alone with no
    // reachable CTC/telnet cannot extract hashes/tables, so gate the
    // Java branch on hasJavaDeploy rather than hasJavaAdmin.
    'download_hashes':    (isAbapStack && hasCreds) ||
                          (isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy)),
    'download_secstore':  hasCreds,                   // need credentials/access
    'download_java_secstore': isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy),
    'view_java_secstore':     n && n.java_secstore_checked,
    'download_table':     (isAbapStack && hasCreds) ||
                          (isJavaStack && (hasCve31324 || hasGwVuln || hasJavaDeploy)),
    'impact_assess':      hasCreds,                   // need credentials/access
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
    'create_tcpip':     hasCreds,                   // need credentials/access
    'propagate':        hasCreds,                   // need access to propagate from
    'cleanup':          hasCreatedUsers,             // need created users to clean up
    'client_roles':     hasCreds,                   // need credentials/access
    'set_type':         true,                       // always available
    'set_db_type':      true,                       // always available
    'set_os_type':      true,                       // always available
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
    'retrieve_rfcs':    'Provide credentials or create a user first',
    'test_rfcs':        'Retrieve RFC connections first',
    'read_java_destinations': (javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). System is hardened — data extraction not available from here.'
        : 'Requires Java/dual-stack + CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint'),
    'download_hashes':    (isJavaStack && !isAbapStack && javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). Hashes cannot be extracted from a Java-only hardened target.'
        : 'Provide credentials or create a user first'),
    'download_secstore':  'Provide credentials or create a user first',
    'download_java_secstore': (javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). System is hardened — data extraction not available from here.'
        : 'Requires Java/dual-stack + CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint'),
    'view_java_secstore':     'Run Download Java Secure Store first',
    'download_table':     (isJavaStack && !isAbapStack && javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). Tables cannot be dumped from a Java-only hardened target.'
        : 'Provide credentials or create a user first'),
    'impact_assess':      'Provide credentials or create a user first',
    'impact_view':        'Run impact assessment first',
    'impact_assess_java': (javaDeployBlocked
        ? 'RECON admin user exists but no JSP-deploy primitive is reachable (CTC ConfigServlet removed, admin telnet firewalled). System is hardened — data extraction not available from here.'
        : 'Requires Java/dual-stack + CVE-2025-31324, GW SAPXPG, or a Java admin user with a reachable CTC / telnet endpoint'),
    'os_terminal':      'Requires an OS-exec path: vulnerable GW (any stack), ABAP+created-user (SXPG), or CVE-2025-31324 webshell (Java)',
    'reverse_shell':    'Requires an OS-exec path: vulnerable GW (any stack), ABAP+created-user (SXPG), or CVE-2025-31324 webshell (Java)',
    'create_tcpip':     'Provide credentials or create a user first',
    'propagate':        'Provide credentials or create a user first',
    'cleanup':          'No created users to clean up',
    'client_roles':     'Provide credentials or create a user first',
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
    'set_telnet_override':        !isJavaStack,
    'impact_assess':              !isAbapStack,
    'lpe':                        !isAbapStack,
    'impact_assess_java':         !isJavaStack,
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
    case 'retrieve_rfcs':
      await api('POST', `node/${sid}/retrieve_rfcs`); break;
    case 'test_rfcs':
      await api('POST', `node/${sid}/test_rfcs`); break;
    case 'download_hashes': {
      const nh = (mapState.nodes || {})[sid];
      const sysT = (nh && nh.system_type || '').toUpperCase();
      const isJavaOnly = sysT.indexOf('JAVA') !== -1 && sysT.indexOf('ABAP') === -1;
      if (isJavaOnly) {
        if (!confirm('Extract Java password material?\n\n' +
                      'Pulls UME_STRINGS j_user/j_password pairs (UME hashes) ' +
                      'AND J2EE_CONFIGENTRY password-like rows (cleartext after ' +
                      'SecStoreFS decryption).  Output saved to states/ as ' +
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
    case 'cleanup':
      if (confirm(`Delete SAPMAP00 user from ${sid}?`))
        await api('POST', `node/${sid}/cleanup`);
      break;
    case 'client_roles':
      await api('POST', `node/${sid}/client_roles`); break;
    case 'set_type': showTypeModal(sid); break;
    case 'set_db_type': showDbTypeModal(sid); break;
    case 'set_os_type': showOsTypeModal(sid); break;
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
      <div class="info-row"><span class="info-label">User:</span><span class="info-val">${escHtml(conn.rfc_user || '?')}</span></div>
      ${conn.secstore_password ? `<div class="info-row"><span class="info-label">SecStore Pwd:</span><span class="info-val ss-reveal" style="color:#3fb950;cursor:pointer"><span class="ss-masked">&#9679;&#9679;&#9679;&#9679; (${conn.secstore_password.length} chars) — click to reveal</span><span class="ss-plain" style="display:none">${escHtml(conn.secstore_password)}</span></span></div>` : ''}
      <div class="info-section" style="color:#8b949e;font-size:11px">
        Java HTTP destination — if ${escHtml(conn.rfc_user || 'the user')} has UME admin, you can log into the target Java stack's NWA / CTC ConfigServlet / Telnet console with these creds and drop a JSP for full OS access.
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
      ${(!isTypeT && !isHttp && conn.logon_successful && conn.has_sap_all && conn.target_sid) ?
        `<button class="btn" style="background:#b33;color:#fff" onclick="createUserViaRfc('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}','${escHtml(conn.target_sid)}')">Create Remote User</button>` : ''}
      ${isHttp ? '' :
        `<button class="btn" onclick="testSingleRfc('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}',${connIdx})">Test Connection</button>`}
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
      const catColors = {rfc:'#f0883e',db:'#58a6ff',cts:'#3fb950',smtp:'#bc8cff',hmac:'#484f58',pse:'#484f58',other:'#484f58'};
      const catLabels = {rfc:'RFC',db:'DB',cts:'CTS',smtp:'SMTP',hmac:'HMAC',pse:'PSE',other:'?'};
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
            '<span class="detail-key" style="color:' + col + ';min-width:36px">' + lbl + '</span>' +
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
    {stickUntilClose: true}
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
  const methodSel = document.getElementById('term-method');
  // Enable/disable method options based on what's available
  methodSel.options[0].disabled = !hasGw;    // gateway
  methodSel.options[1].disabled = !hasCreated; // sxpg
  methodSel.options[2].disabled = !hasCve;   // cve_31324
  // Default: prefer CVE-31324 on Java nodes (unauth path, output via shell),
  // otherwise GW exploit, otherwise SXPG.
  methodSel.value = hasCve ? 'cve_31324' : (hasGw ? 'gateway' : 'sxpg');
  // Info text
  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated) info.push('SXPG: user available');
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
  const methodSel = document.getElementById('shell-method');
  methodSel.options[0].disabled = !hasGw;
  methodSel.options[1].disabled = !hasCreated;
  methodSel.options[2].disabled = !hasCve;
  methodSel.value = hasCve ? 'cve_31324' : (hasGw ? 'gateway' : 'sxpg');

  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated) info.push('SXPG: user available');
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

async function resetRFCCache() {
  if (confirm('Reset the RFC check cache? This allows re-testing all connections.'))
    await api('POST', 'actions/reset_rfc_cache');
}
async function viewRFCCache() {
  const res = await api('GET', 'actions/rfc_check_list');
  const entries = res.entries || [];
  if (entries.length === 0) { alert('RFC check list is empty.'); return; }
  const lines = entries.map(e => {
    const status = e.logon_ok ? 'LOGON OK' : e.ping_ok ? 'PING OK' : e.error ? 'ERROR' : 'FAILED';
    const lat = e.latency_ms ? ` ${e.latency_ms}ms` : '';
    return `${e.destination}: ${status}${lat}`;
  });
  alert(`RFC Check List (${entries.length} entries):\n\n` + lines.join('\n'));
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

// --- View controls ---
function zoomIn() { viewBoxUserControlled = true; viewBox.w *= 0.8; viewBox.h *= 0.8; applyViewBox(); }
function zoomOut() { viewBoxUserControlled = true; viewBox.w *= 1.25; viewBox.h *= 1.25; applyViewBox(); }
function fitMap() { viewBoxUserControlled = false; viewBox.x = 0; viewBox.y = 0; viewBox.w = 1200; viewBox.h = 800; viewBox._nodeCount = 0; applyViewBox(); updateMap(); }
function resetLayout() {
  viewBoxUserControlled = false;
  viewBox.x = 0; viewBox.y = 0; viewBox._nodeCount = 0;
  Object.values(mapState.nodes || {}).forEach(n => { n._x = null; n._y = null; });
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

function layoutCircle() {
  const sids = _loSortedNodeKeys();
  if (sids.length === 0) return;
  const nodes = mapState.nodes;
  // Radius scales with node count so boxes don't overlap on the ring.
  const minR = 360;
  const circ = sids.length * (_LO_BOX_W + _LO_MARGIN);
  const r = Math.max(minR, circ / (2 * Math.PI));
  // Centre of the ring; +radius padding on each side leaves room
  // for boxes to extend past the ring centre coordinate.
  const cx = r + _LO_BOX_W;
  const cy = r + _LO_BOX_H;
  sids.forEach((sid, i) => {
    const angle = (2 * Math.PI * i) / sids.length - Math.PI / 2;  // start at top
    _loCenter(nodes[sid], cx + r * Math.cos(angle),
                              cy + r * Math.sin(angle));
  });
  fitMap();
  updateMap();
}

function layoutStar() {
  // Hub-and-spoke: pick the most-connected node as hub, ring the rest.
  const sids = _loSortedNodeKeys();
  if (sids.length === 0) return;
  const nodes = mapState.nodes;
  const conns = mapState.connections || [];
  // Tally edge counts per SID — both source and target sides count.
  const deg = {};
  sids.forEach(s => { deg[s] = 0; });
  conns.forEach(c => {
    if (deg[c.source_sid] != null) deg[c.source_sid]++;
    if (deg[c.target_sid] != null) deg[c.target_sid]++;
  });
  // Pick highest-degree node; tie-break by SID for stability.
  let hub = sids[0];
  sids.forEach(s => {
    if (deg[s] > deg[hub] ||
        (deg[s] === deg[hub] && s < hub)) hub = s;
  });
  const spokes = sids.filter(s => s !== hub);
  const r = Math.max(360,
      spokes.length * (_LO_BOX_W + _LO_MARGIN) / (2 * Math.PI));
  const cx = r + _LO_BOX_W;
  const cy = r + _LO_BOX_H;
  // Hub at centre.
  _loCenter(nodes[hub], cx, cy);
  // Spokes around the ring (sorted, start at top).
  spokes.forEach((sid, i) => {
    const angle = (2 * Math.PI * i) / spokes.length - Math.PI / 2;
    _loCenter(nodes[sid], cx + r * Math.cos(angle),
                              cy + r * Math.sin(angle));
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
  layerKeys.forEach((lk, layerIdx) => {
    const row = buckets[lk].sort();
    const yC = _LO_MARGIN + layerIdx * ySpacing + _LO_BOX_H / 2;
    const xPad = (rowWidth - row.length * xSpacing) / 2;
    row.forEach((sid, i) => {
      const xC = _LO_MARGIN + xPad + i * xSpacing + _LO_BOX_W / 2;
      _loCenter(nodes[sid], xC, yC);
    });
  });
  fitMap();
  updateMap();
}

function layoutByStack() {
  // Group nodes into clusters by system_type.  Each cluster gets its
  // own column; nodes within a cluster stack vertically.  Saproute
  // and unknown-stack nodes get their own columns at the right edge.
  const sids = _loSortedNodeKeys();
  if (sids.length === 0) return;
  const nodes = mapState.nodes;

  function bucketOf(n) {
    const t = (n.system_type || '').toUpperCase();
    if (t === 'SAPROUTER') return 'SAProuter';
    if (t.includes('ABAP') && t.includes('JAVA')) return 'ABAP+JAVA';
    if (t.includes('ABAP')) return 'ABAP';
    if (t.includes('JAVA')) return 'JAVA';
    return 'Other';
  }
  const order = ['ABAP', 'ABAP+JAVA', 'JAVA', 'SAProuter', 'Other'];
  const clusters = {};
  order.forEach(b => { clusters[b] = []; });
  sids.forEach(sid => {
    const b = bucketOf(nodes[sid]);
    if (!clusters[b]) clusters[b] = [];
    clusters[b].push(sid);
  });
  // Drop empty clusters; keep order
  const populated = order.filter(b => clusters[b].length > 0);
  const xSpacing = _LO_BOX_W + _LO_MARGIN * 2;
  const ySpacing = _LO_BOX_H + _LO_MARGIN;
  populated.forEach((b, colIdx) => {
    clusters[b].sort().forEach((sid, rowIdx) => {
      const xC = _LO_MARGIN + colIdx * xSpacing + _LO_BOX_W / 2;
      const yC = _LO_MARGIN + 30 + rowIdx * ySpacing + _LO_BOX_H / 2;
      _loCenter(nodes[sid], xC, yC);
    });
  });
  fitMap();
  updateMap();
}
function applyViewBox() {
  document.getElementById('map-svg').setAttribute('viewBox',
    `${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`);
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

function updateActivityBar() {
  const bar = document.getElementById('activity-bar');
  const keys = Object.keys(activeTasks);
  if (keys.length === 0) {
    bar.classList.remove('active');
    return;
  }
  bar.classList.add('active');
  // Build descriptive text: group by SID
  const parts = [];
  for (const key of keys) {
    const label = activeTasks[key];
    // Key format: "SID:operation" or "_global_op"
    const colonIdx = key.indexOf(':');
    const sid = colonIdx > 0 && !key.startsWith('_') ? key.substring(0, colonIdx) : '';
    parts.push(sid ? `${sid}: ${label}` : label);
  }
  document.getElementById('activity-text').textContent = parts.join(' | ');
}

function _nodeHasActiveTask(sid) {
  for (const key in activeTasks) {
    if (key === sid + ':' || key.startsWith(sid + ':')) return true;
  }
  return false;
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
  if (!e.target.closest('.info-panel') && !e.target.closest('.edge-line'))
    document.getElementById('info-panel').classList.remove('visible');
});

document.addEventListener('contextmenu', e => {
  const nodeBox = e.target.closest('.node-box');
  const mapSvg = document.getElementById('map-svg');
  const mapContainer = document.getElementById('map-container');
  hideCtxMenu();
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

// --- Init ---
startPolling();
</script>
</body>
</html>"""
