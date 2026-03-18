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
.console-container {
  height: 180px; flex-shrink: 0; display: flex; flex-direction: column;
  border-top: 1px solid #30363d; min-height: 0;
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
  font-size: 12px; color: #c9d1d9;
}
.ctx-item:hover { background: #30363d; }
.ctx-item.disabled { color: #484f58; cursor: default; }
.ctx-item.disabled:hover { background: transparent; }
.ctx-sep { border-top: 1px solid #30363d; margin: 4px 0; }

/* === Info Panel (connection details) === */
.info-panel {
  display: none; position: fixed; z-index: 1500;
  background: #1c2128; border: 1px solid #30363d; border-radius: 8px;
  width: 420px; max-height: 500px; overflow-y: auto; padding: 16px;
  box-shadow: 0 8px 24px rgba(0,0,0,.5);
}
.info-panel.visible { display: block; }
.info-panel h3 { font-size: 13px; color: #f0883e; margin-bottom: 10px; }
.info-panel .info-row { display: flex; margin: 3px 0; font-size: 12px; }
.info-panel .info-label { color: #8b949e; width: 110px; flex-shrink: 0; }
.info-panel .info-val { color: #e6edf3; }
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
      <div class="dd-item" onclick="if(confirm('Exit SAPMAP?'))window.close()">&#10060; Exit</div>
    </div>
  </div>
  <div class="menu-item">Scan
    <div class="menu-dropdown">
      <div class="dd-item" onclick="toggleToolbar()">&#128295; Toggle Scan Panel</div>
    </div>
  </div>
  <div class="menu-item">Actions
    <div class="menu-dropdown">
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
    </div>
  </div>
  <div class="menu-item">View
    <div class="menu-dropdown">
      <div class="dd-item" onclick="zoomIn()">&#128269; Zoom In</div>
      <div class="dd-item" onclick="zoomOut()">&#128269; Zoom Out</div>
      <div class="dd-item" onclick="fitMap()">&#128208; Fit to Window</div>
      <div class="dd-item" onclick="resetLayout()">&#128260; Reset Layout</div>
      <div class="dd-sep"></div>
      <div class="dd-item" onclick="toggleConsole()">&#128203; Toggle Console</div>
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
    <span class="legend-item"><span class="legend-swatch" style="background:#ff6b35;border:2px dashed #ff6b35;background:transparent"></span> TCP/IP (sapxpg)</span>
    <span style="flex:1"></span>
    <label style="cursor:pointer;display:flex;align-items:center;gap:6px;padding:2px 10px;border:1px solid #30363d;border-radius:4px;background:#161b22;color:#c9d1d9;font-size:11px"><input type="checkbox" id="show-unknown" style="accent-color:#f0883e;width:14px;height:14px" onchange="updateMap()"> Show unknown targets</label>
  </div>

  <!-- Console restore button (visible when console is minimized) -->
  <div id="console-restore" style="display:none;height:24px;flex-shrink:0;background:#161b22;border-top:1px solid #30363d;cursor:pointer;text-align:right;padding-right:12px;line-height:24px;color:#8b949e;font-size:12px;user-select:none" onclick="toggleConsole()" title="Show Console">&#9650; Console</div>

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
  <div class="ctx-item" data-action="details">&#128269; View System Details</div>
  <div class="ctx-item" data-action="findings">&#128203; View SAPology Findings</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="credentials">&#128273; Provide Credentials</div>
  <div class="ctx-item" data-action="rfc_system_info">&#128225; RFC System Info</div>
  <div class="ctx-item" data-action="check_gw">&#128270; Check GW Vulnerability</div>
  <div class="ctx-item" data-action="create_user_gw">&#128100; Create User (GW Exploit)</div>
  <div class="ctx-item" data-action="create_user_creds">&#128100; Create User (via Credentials)</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="deep_scan">&#128260; Deep Scan (full SAPology)</div>
  <div class="ctx-item" data-action="retrieve_rfcs">&#128225; Retrieve RFC Connections</div>
  <div class="ctx-item" data-action="test_rfcs">&#129514; Test RFC Connections+Retrieve Profiles</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="download_hashes">&#128229; Download Password Hashes</div>
  <div class="ctx-item" data-action="download_table">&#128229; Download Table Data</div>
  <div class="ctx-item" data-action="os_terminal">&#128187; OS Command Terminal</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="create_tcpip">&#128279; Create TCP/IP Dest (sapxpg)</div>
  <div class="ctx-item" data-action="propagate">&#128640; Propagate (exploit next hop)</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="cleanup">&#128465; Delete SAPMAP00 User</div>
  <div class="ctx-item" data-action="client_roles">&#128202; Retrieve Client Roles</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="set_type">&#9881; Set System Type</div>
  <div class="ctx-item" data-action="set_db_type">&#9881; Set DB Type</div>
  <div class="ctx-item" data-action="set_os_type">&#9881; Set OS Type</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="delete_system" style="color:#f85149">&#128465; Delete System from Map</div>
</div>

<!-- Map Background Context Menu -->
<div class="ctx-menu" id="map-ctx-menu">
  <div class="ctx-item" data-action="map_add_system">&#10133; Add System Manually</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="map_propagate_all">&#128640; Auto-Propagate All</div>
  <div class="ctx-item" data-action="map_cleanup_all">&#129529; Cleanup All Users</div>
  <div class="ctx-item" id="map-ctx-check-all-gw" data-action="map_check_all_gw">&#128272; Check All GW Vulnerabilities</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-action="map_fit">&#128208; Fit to Window</div>
  <div class="ctx-item" data-action="map_reset_layout">&#128260; Reset Layout</div>
</div>

<!-- Connection Info Panel -->
<div class="info-panel" id="info-panel"></div>

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
    <div class="form-actions">
      <button class="btn btn-primary" onclick="addSystem()">Add System</button>
      <button class="btn" onclick="closeModal('add-system-modal')">Cancel</button>
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
  <div class="modal" style="width:620px;max-width:90vw">
    <h3>&#128187; OS Command Terminal — <span id="term-sid"></span></h3>
    <div style="font-size:11px;color:#8b949e;margin-bottom:8px" id="term-info"></div>
    <div class="form-row" style="display:flex;gap:8px;align-items:flex-end">
      <div style="flex:1">
        <label>Method</label>
        <select id="term-method" style="width:100%">
          <option value="gateway">Gateway (unauthenticated)</option>
          <option value="sxpg">SXPG (via SAP_ALL user)</option>
        </select>
      </div>
    </div>
    <div class="form-row" style="display:flex;gap:8px;align-items:flex-end">
      <div style="flex:1">
        <label>Command</label>
        <input type="text" id="term-cmd" placeholder="e.g. /bin/sh or cmd.exe" style="width:100%">
      </div>
      <div style="flex:2">
        <label>Parameters</label>
        <input type="text" id="term-params" placeholder="e.g. -c whoami  or  /C dir" style="width:100%"
               onkeydown="if(event.key==='Enter'){event.preventDefault();termExec();}">
      </div>
      <button class="btn btn-primary" onclick="termExec()" style="white-space:nowrap">Run</button>
    </div>
    <div id="term-output" style="background:#010409;border:1px solid #30363d;border-radius:4px;
      padding:8px;margin-top:8px;font-family:monospace;font-size:12px;color:#7ee787;
      min-height:120px;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-all">
      Ready. Enter a command above and click Run.
    </div>
    <div class="form-actions" style="margin-top:8px">
      <button class="btn" onclick="document.getElementById('term-output').textContent=''">Clear</button>
      <button class="btn" onclick="closeModal('terminal-modal')">Close</button>
    </div>
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
  await api('POST', 'scan/stop');
  document.getElementById('st-status').textContent = 'Cancelled';
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
  const BOX_W = 240, BOX_H = 160, MARGIN = 60;
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
    if (conn.has_sap_all && conn.logon_successful) {
      color = '#e74c3c'; width = 6;
    } else if (conn.sapxpg_remote_works) {
      color = '#ff6b35'; width = 5.5; dashArray = '8,4';
    } else if (conn.logon_successful) {
      color = '#2ecc71'; width = 5;
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

    if (n.has_critical_finding || n.gw_vulnerable) { borderColor = '#8b0000'; borderWidth = 6; }

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

    // PRD indicator bar
    if (n.is_production) {
      html += `<rect x="${x+10}" y="${y+BOX_H-28}" width="${BOX_W-20}" height="8" rx="4" fill="#8b0000" opacity="0.7" />`;
      html += `<text x="${x+BOX_W/2}" y="${y+BOX_H-32}" text-anchor="middle" font-size="9" fill="#f85149" font-weight="bold">PRD</text>`;
    } else if (clients.length > 0) {
      html += `<rect x="${x+10}" y="${y+BOX_H-28}" width="${BOX_W-20}" height="8" rx="4" fill="#e67e22" opacity="0.4" />`;
    }

    // Finding count badge
    const findings = n.findings || [];
    if (findings.length > 0) {
      const maxSev = Math.max(...findings.map(f => f.severity || 1));
      const badgeColor = maxSev >= 5 ? '#da3633' : maxSev >= 4 ? '#e67e22' : '#d29922';
      html += `<circle cx="${x+BOX_W-14}" cy="${y+BOX_H-14}" r="11" fill="${badgeColor}" />`;
      html += `<text x="${x+BOX_W-14}" y="${y+BOX_H-10}" text-anchor="middle" font-size="10" fill="#fff">${findings.length}</text>`;
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
  const hasGwPort = n && (n.instances || []).some(i => Object.entries(i.ports || {}).some(([p,s]) => s === 'gateway' || (p >= 3300 && p <= 3399)));
  const hasFindings = n && (n.findings || []).length > 0;
  const hasCreatedUsers = n && (n.created_users || []).length > 0;
  const hasRFCs = (mapState.connections || []).some(c => c.source_sid === sid);
  const hasUntested = (mapState.connections || []).some(c => c.source_sid === sid && !c.tested);

  // Enable/disable rules per action
  const rules = {
    'details':          true,                       // always available
    'findings':         true,                       // always (shows "no findings" if empty)
    'credentials':      true,                       // always available
    'rfc_system_info':  hasGwPort,                   // need a gateway port
    'check_gw':         hasGwPort,                   // need a gateway port
    'create_user_gw':   hasGwVuln,                  // need GW vulnerability
    'create_user_creds': hasCreds,                  // need credentials
    'deep_scan':        true,                       // always available
    'retrieve_rfcs':    hasCreds,                   // need credentials/access
    'test_rfcs':        hasCreds && hasRFCs,        // need access + existing RFCs
    'download_hashes':  hasCreds,                   // need credentials/access
    'download_table':   hasCreds,                   // need credentials/access
    'os_terminal':      hasGwVuln || hasCreatedUsers, // need GW vuln or created user
    'create_tcpip':     hasCreds,                   // need credentials/access
    'propagate':        hasCreds,                   // need access to propagate from
    'cleanup':          hasCreatedUsers,             // need created users to clean up
    'client_roles':     hasCreds,                   // need credentials/access
    'set_type':         true,                       // always available
    'set_db_type':      true,                       // always available
    'set_os_type':      true,                       // always available
    'delete_system':    true,                       // always available
  };

  // Tooltip hints for disabled items
  const hints = {
    'rfc_system_info':  'No gateway port detected',
    'check_gw':         'No gateway port detected',
    'create_user_gw':   'Requires a vulnerable RFC Gateway',
    'create_user_creds': 'Provide credentials first',
    'retrieve_rfcs':    'Provide credentials or create a user first',
    'test_rfcs':        'Retrieve RFC connections first',
    'download_hashes':  'Provide credentials or create a user first',
    'download_table':   'Provide credentials or create a user first',
    'os_terminal':      'Requires vulnerable gateway or created user with SAP_ALL',
    'create_tcpip':     'Provide credentials or create a user first',
    'propagate':        'Provide credentials or create a user first',
    'cleanup':          'No created users to clean up',
    'client_roles':     'Provide credentials or create a user first',
  };

  // Apply enable/disable state to each menu item
  menu.querySelectorAll('.ctx-item[data-action]').forEach(item => {
    const action = item.getAttribute('data-action');
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
    case 'create_user_gw':
      await api('POST', `node/${sid}/create_user`, { method: 'gw_exploit' }); break;
    case 'create_user_creds':
      await api('POST', `node/${sid}/create_user`, { method: 'credentials' }); break;
    case 'deep_scan':
      await api('POST', `node/${sid}/deep_scan`); break;
    case 'retrieve_rfcs':
      await api('POST', `node/${sid}/retrieve_rfcs`); break;
    case 'test_rfcs':
      await api('POST', `node/${sid}/test_rfcs`); break;
    case 'download_hashes':
      await api('POST', `node/${sid}/download_hashes`); break;
    case 'download_table':
      document.getElementById('table-modal').classList.add('visible'); break;
    case 'os_terminal': showTerminalModal(sid); break;
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

function showConnInfo(e, connIdx) {
  e.stopPropagation();
  const conn = (mapState.connections || [])[connIdx];
  if (!conn) return;

  const panel = document.getElementById('info-panel');
  const isTypeT = !!conn.sapxpg_remote_works;
  const connType = isTypeT ? 'T' : '3';
  let risk;
  if (isTypeT) {
    risk = conn.ping_ok ? 'CRITICAL' : conn.tested ? 'LOW' : 'UNKNOWN';
  } else {
    risk = conn.has_sap_all && conn.logon_successful ? 'CRITICAL' :
      conn.logon_successful ? 'MEDIUM' : conn.tested ? 'LOW' : 'UNKNOWN';
  }
  const riskClass = 'risk-' + risk.toLowerCase();

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

  panel.innerHTML = `
    <h3>${isTypeT ? 'TCP/IP' : 'RFC'} Connection Details</h3>
    <div class="info-row"><span class="info-label">Source:</span><span class="info-val">${escHtml(conn.source_sid)} (${escHtml(conn.source_host)})</span></div>
    <div class="info-row"><span class="info-label">Target:</span><span class="info-val">${escHtml(conn.target_sid || '?')} (${escHtml(conn.target_host || '?')})</span></div>
    <div class="info-row"><span class="info-label">Destination:</span><span class="info-val">${escHtml(conn.destination_name)} (Type ${connType})</span></div>
    ${isTypeT ? `
      <div class="info-row"><span class="info-label">Port:</span><span class="info-val">${escHtml(gwPort)}</span></div>
    ` : `
      <div class="info-row"><span class="info-label">Client:</span><span class="info-val">${escHtml(conn.client || '?')}</span></div>
      <div class="info-row"><span class="info-label">RFC User:</span><span class="info-val">${escHtml(conn.rfc_user || '?')}</span></div>
    `}
    ${profilesHtml ? `<div class="info-section"><strong style="font-size:11px;color:#8b949e">Profiles</strong><div class="profile-list">${profilesHtml}</div></div>` : ''}
    ${rolesHtml ? `<div class="info-section"><strong style="font-size:11px;color:#8b949e">Roles</strong><div class="profile-list">${rolesHtml}</div></div>` : ''}
    ${conn.user_detail_error ? `<div class="info-section" style="color:#d29922;font-size:11px">${escHtml(conn.user_detail_error)}</div>` : ''}
    <div class="info-section">
      <strong style="font-size:11px;color:#8b949e">/SDF/RFC_CHECK</strong>
      ${conn.tested ? `
        <div class="info-row"><span class="info-label">Ping:</span><span class="info-val">${conn.ping_ok ? 'OK' : 'Failed'}${conn.latency_ms ? ' ('+conn.latency_ms+'ms)' : ''}</span></div>
        ${isTypeT ? '' : `<div class="info-row"><span class="info-label">Logon:</span><span class="info-val">${conn.logon_successful ? '&#9989; RFC Logon successful.' : (conn.logon_tested ? '&#10060; Failed' : '&#9898; Not tested')}</span></div>`}
      ` : '<div style="color:#484f58;font-size:11px;margin-top:4px">Not tested yet</div>'}
    </div>
    <div class="info-section">
      <div class="info-row"><span class="info-label">Risk:</span><span class="info-val"><span class="risk-badge ${riskClass}">${risk}</span></span></div>
    </div>
    <div style="text-align:right;margin-top:8px;display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap">
      ${(!isTypeT && conn.logon_successful && conn.has_sap_all && conn.target_sid) ?
        `<button class="btn" style="background:#b33;color:#fff" onclick="createUserViaRfc('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}','${escHtml(conn.target_sid)}')">Create Remote User</button>` : ''}
      <button class="btn" onclick="testSingleRfc('${escHtml(conn.source_sid)}','${escHtml(conn.destination_name)}',${connIdx})">Test Connection</button>
      <button class="btn" onclick="document.getElementById('info-panel').classList.remove('visible')">Close</button>
    </div>
  `;
  panel.style.left = Math.min(e.clientX, window.innerWidth - 440) + 'px';
  panel.style.top = Math.min(e.clientY, window.innerHeight - 520) + 'px';
  panel.classList.add('visible');
}

async function testSingleRfc(sid, destName, connIdx) {
  await api('POST', `node/${sid}/test_rfc_single`, { destination_name: destName });
  startPolling();
  // Re-open the info panel after a short delay to show updated results
  setTimeout(() => {
    const conn = (mapState.connections || [])[connIdx];
    if (conn) {
      const panel = document.getElementById('info-panel');
      const fakeEvent = { stopPropagation: ()=>{}, clientX: parseInt(panel.style.left), clientY: parseInt(panel.style.top) };
      showConnInfo(fakeEvent, connIdx);
    }
  }, 3000);
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
      <div class="detail-row"><span class="detail-key">GW Vulnerable</span><span class="detail-val">${n.gw_vulnerable ? '<span style="color:#f85149">YES</span>' : 'No'}</span></div>
    </div>
    <div class="detail-section">
      <h4>Instances</h4>
      ${(n.instances || []).map(i => `<div class="detail-row"><span class="detail-key">${escHtml(i.instance_nr)}</span><span class="detail-val">${escHtml(i.ip)} — Ports: ${Object.keys(i.ports||{}).sort().join(', ')}</span></div>`).join('')}
    </div>
    <div class="detail-section">
      <h4>Clients</h4>
      ${(n.clients || []).map(c => { const nr = typeof c === 'object' ? (c.nr||'?') : String(c); const cat = typeof c === 'object' ? (c.category||'') : ''; const roleMap = {P:'Production',S:'SAP Reference Client',T:'Test',C:'Customising',D:'Demo',E:'Training'}; const label = roleMap[cat]; return `<div class="detail-row"><span class="detail-key">${escHtml(nr)}</span><span class="detail-val">${cat === 'P' ? '<span style="color:#f85149">Production</span>' : label ? escHtml(label) : escHtml(cat)}</span></div>`; }).join('') || '<div style="color:#484f58">None enumerated</div>'}
    </div>
    <div class="detail-section">
      <h4>Created Users (${(n.created_users||[]).length})</h4>
      ${(n.created_users || []).map(u => `<div class="detail-row"><span class="detail-key">${escHtml(u.username)}</span><span class="detail-val">Client ${escHtml(u.client)} via ${escHtml(u.method)}</span></div>`).join('') || '<div style="color:#484f58">None</div>'}
    </div>
  `;
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

function closeModal(id) { document.getElementById(id).classList.remove('visible'); }

function showAddSystemModal() {
  document.getElementById('add-sid').value = '';
  document.getElementById('add-ip').value = '';
  document.getElementById('add-instance').value = '00';
  document.getElementById('add-system-modal').classList.add('visible');
  document.getElementById('add-sid').focus();
}
async function addSystem() {
  const sid = document.getElementById('add-sid').value.trim().toUpperCase();
  const ip = document.getElementById('add-ip').value.trim();
  const inst = document.getElementById('add-instance').value.trim();
  if (!sid || !ip || !inst) { alert('All fields are required'); return; }
  const res = await api('POST', 'node/add', { sid, ip, instance_nr: inst });
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
function showTerminalModal(sid) {
  const n = (mapState.nodes || {})[sid];
  document.getElementById('term-sid').textContent = sid;
  const hasGw = n && n.gw_vulnerable;
  const hasCreated = n && (n.created_users || []).length > 0;
  const methodSel = document.getElementById('term-method');
  // Enable/disable method options based on what's available
  methodSel.options[0].disabled = !hasGw;   // gateway
  methodSel.options[1].disabled = !hasCreated; // sxpg
  methodSel.value = hasGw ? 'gateway' : 'sxpg';
  // Info text
  let info = [];
  if (hasGw) info.push('Gateway: vulnerable');
  if (hasCreated) info.push('SXPG: user available');
  document.getElementById('term-info').textContent = info.join(' | ') || 'No execution method available';
  // Pre-fill command based on OS
  const os = (n && n.os_type || '').toLowerCase();
  const cmdInput = document.getElementById('term-cmd');
  const paramInput = document.getElementById('term-params');
  if (os.includes('windows') || os.includes('nt')) {
    cmdInput.value = 'cmd.exe';
    paramInput.value = '/C whoami';
  } else {
    cmdInput.value = '/bin/sh';
    paramInput.value = '-c whoami';
  }
  document.getElementById('term-output').textContent = 'Ready. Enter a command above and click Run.';
  document.getElementById('terminal-modal').classList.add('visible');
  paramInput.focus();
}

async function termExec() {
  const sid = document.getElementById('term-sid').textContent;
  const method = document.getElementById('term-method').value;
  const command = document.getElementById('term-cmd').value.trim();
  const params = document.getElementById('term-params').value.trim();
  const out = document.getElementById('term-output');
  if (!command) { alert('Enter a command'); return; }

  out.textContent += `\n$ ${command} ${params}\n`;
  out.textContent += '(executing...)\n';
  out.scrollTop = out.scrollHeight;

  try {
    const res = await api('POST', `node/${sid}/exec_command`, { method, command, params });
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
}

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
  if (nodeCount < 2) { alert('Need at least 2 systems on the map.'); return; }
  if (confirm(`Check RFC gateway vulnerability on all ${nodeCount} systems on the map?`))
    await api('POST', 'actions/check_all_gw');
  startPolling();
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
function applyViewBox() {
  document.getElementById('map-svg').setAttribute('viewBox',
    `${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`);
}
function toggleConsole() {
  const c = document.getElementById('console-container');
  const r = document.getElementById('console-restore');
  const hidden = c.style.display === 'none';
  c.style.display = hidden ? 'flex' : 'none';
  r.style.display = hidden ? 'none' : 'block';
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
  if (!nodeBox && (e.target === mapSvg || e.target === mapContainer || mapSvg.contains(e.target))) {
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
    case 'map_check_all_gw': checkAllGateways(); break;
    case 'map_fit': fitMap(); break;
    case 'map_reset_layout': resetLayout(); break;
  }
});
document.addEventListener('click', () => hideMapCtxMenu());

// --- Init ---
startPolling();
</script>
</body>
</html>"""
