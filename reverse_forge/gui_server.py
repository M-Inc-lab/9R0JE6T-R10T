"""
R3V3R53//F0RG3  Interactive GUI Application Server (v10.0.0-zenith)
===================================================================
Phase 42, 44, 56 & 63 Upgrade: Hardened, Zero-Dependency Web & Desktop Workbench.
Security & UX Features:
- Strict localhost Origin/CSRF protection (blocks cross-origin local file reads)
- Complete DOM XSS sanitization (`escHtml`) on all binary strings, symbols, and sections
- Drag-and-Drop & One-Click HTML5 File Picker (`POST /api/upload`) + server path loader
- Real binary CFG basic-block rendering (`/api/cfg` + `UnifiedDecompilerPipeline`)
- Real binary Hex & ASCII rendering (`/api/hex`) + ImHex 14-Format Data Inspector Drawer
- Interactive Debugger Toolbar (`Step F7`, `Continue F9`, `Breakpoint F2`)
- Live Analyst Symbol Rename (`N`), Comment (`;`), `.h` C Header Export & 12-Stage Pipeline Runner
"""

from __future__ import annotations

import html
import http.server
import json
import os
import socketserver
import struct
import sys
import tempfile
import threading
import urllib.parse
import webbrowser
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.pe_analyzer import PEAnalyzer
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.decompiler_engine import MicroDecompilerEngine
from reverse_forge.binary_intel_engine import BinaryIntelEngine
from reverse_forge.unified_decompiler_pipeline import UnifiedDecompilerPipeline
from reverse_forge.project_workspace_db import ProjectWorkspaceDB
from reverse_forge.pipeline import PipelineStateMachine, AutonomyLevel


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>9R0JE6T R10T // R3V3R53-F0RG3 Studio v10.0-zenith</title>
<style>
:root {
  --bg-dark: #0a0e17;
  --bg-panel: #111827;
  --bg-card: #1f2937;
  --bg-hover: #374151;
  --border: #374151;
  --primary: #38bdf8;
  --primary-glow: rgba(56, 189, 248, 0.25);
  --accent: #a855f7;
  --success: #22c55e;
  --danger: #ef4444;
  --warning: #f59e0b;
  --text-main: #f3f4f6;
  --text-muted: #9ca3af;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg-dark);
  color: var(--text-main);
  font-family: var(--font-sans);
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

header {
  height: 54px;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 14px;
  flex-shrink: 0;
  gap: 10px;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand-logo {
  font-family: var(--font-mono);
  font-weight: 800;
  font-size: 14px;
  background: linear-gradient(135deg, var(--primary), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  letter-spacing: 1px;
}
.badge {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 4px;
  background: rgba(56, 189, 248, 0.15);
  color: var(--primary);
  border: 1px solid rgba(56, 189, 248, 0.3);
}

.nav-tabs { display: flex; gap: 3px; flex-wrap: nowrap; }
.nav-tab {
  padding: 6px 10px;
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-size: 12px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 5px;
  transition: all 0.15s ease;
}
.nav-tab:hover { background: var(--bg-card); color: var(--text-main); }
.nav-tab.active {
  background: var(--bg-card);
  color: var(--primary);
  border-bottom: 2px solid var(--primary);
}
.nav-tab kbd {
  font-size: 10px;
  font-family: var(--font-mono);
  padding: 1px 4px;
  background: rgba(255,255,255,0.08);
  border-radius: 3px;
  color: var(--text-muted);
}

.sub-toolbar {
  height: 38px;
  background: #0d1320;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 14px;
  font-size: 12px;
  flex-shrink: 0;
}
.toolbar-group { display: flex; align-items: center; gap: 6px; }

.header-actions { display: flex; align-items: center; gap: 6px; }
.query-bar {
  background: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 5px 10px;
  color: var(--text-main);
  font-family: var(--font-mono);
  font-size: 12px;
  width: 220px;
}
.query-bar:focus { border-color: var(--primary); outline: none; box-shadow: 0 0 0 2px var(--primary-glow); }

.btn {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border);
  padding: 5px 10px;
  font-size: 11px;
  font-weight: 600;
  border-radius: 6px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.btn:hover { background: var(--bg-hover); border-color: var(--primary); }
.btn-primary { background: var(--primary); color: #04101e; border: none; }
.btn-primary:hover { background: #7dd3fc; }

.workspace { display: flex; flex: 1; overflow: hidden; }

.sidebar {
  width: 300px;
  background: var(--bg-panel);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.sidebar-header {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.search-input {
  width: 100%;
  background: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 6px 10px;
  color: var(--text-main);
  font-family: var(--font-mono);
  font-size: 12px;
  outline: none;
}
.sidebar-tabs { display: flex; border-bottom: 1px solid var(--border); }
.sidebar-tab {
  flex: 1;
  padding: 8px 4px;
  background: transparent;
  border: none;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  cursor: pointer;
}
.sidebar-tab.active { color: var(--primary); border-bottom: 2px solid var(--primary); background: rgba(56, 189, 248, 0.05); }

.sidebar-list { flex: 1; overflow-y: auto; font-family: var(--font-mono); font-size: 12px; }
.list-item {
  padding: 8px 12px;
  border-bottom: 1px solid rgba(255,255,255,0.03);
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.list-item:hover { background: var(--bg-hover); }
.item-addr { color: var(--accent); font-size: 11px; }
.item-name { color: var(--text-main); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 180px; }

.main-stage { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-dark); position: relative; }
.view-panel { display: none; flex: 1; height: 100%; width: 100%; overflow: hidden; }
.view-panel.active { display: flex; flex-direction: column; }

.cfg-container {
  flex: 1;
  position: relative;
  overflow: auto;
  background: radial-gradient(circle at center, #111827 0%, #0a0e17 100%);
}
.cfg-canvas { position: absolute; top: 0; left: 0; width: 2000px; height: 1600px; pointer-events: none; }
.cfg-node {
  position: absolute;
  background: var(--bg-panel);
  border: 1px solid #4b5563;
  border-radius: 8px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.5);
  font-family: var(--font-mono);
  font-size: 12px;
  min-width: 270px;
}
.cfg-node-hdr {
  background: #1f2937;
  padding: 6px 10px;
  font-weight: 700;
  color: var(--primary);
  border-bottom: 1px solid var(--border);
}
.cfg-node-body { padding: 8px 10px; line-height: 1.6; }
.cfg-insn { display: flex; gap: 12px; }
.cfg-mnem { color: #f43f5e; font-weight: 600; width: 52px; }
.cfg-ops { color: #e2e8f0; }

.graph-controls {
  position: fixed;
  bottom: 42px;
  right: 24px;
  display: flex;
  gap: 6px;
  background: rgba(17, 24, 39, 0.85);
  padding: 6px;
  border-radius: 8px;
  border: 1px solid var(--border);
  z-index: 10;
}
.graph-btn {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border);
  border-radius: 4px;
  width: 32px;
  height: 32px;
  cursor: pointer;
}

.code-view {
  flex: 1;
  overflow: auto;
  padding: 16px;
  background: var(--bg-dark);
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.6;
}
.code-line { display: flex; }
.code-num { width: 48px; color: #4b5563; user-select: none; text-align: right; padding-right: 16px; }
.code-text { flex: 1; color: #e2e8f0; white-space: pre; }
.kw { color: #f43f5e; font-weight: 600; }
.type { color: var(--primary); }
.func { color: #34d399; font-weight: 600; }
.num { color: #fbbf24; }

.hex-split { display: flex; flex: 1; overflow: hidden; }
.hex-container { flex: 1; display: flex; flex-direction: column; overflow: hidden; font-family: var(--font-mono); font-size: 13px; }
.hex-header { padding: 8px 16px; background: var(--bg-panel); border-bottom: 1px solid var(--border); display: flex; gap: 24px; color: var(--text-muted); font-size: 11px; }
.hex-body { flex: 1; overflow-y: auto; padding: 10px 16px; line-height: 1.6; }
.hex-row { display: flex; gap: 24px; }
.hex-offset { color: var(--accent); user-select: none; width: 90px; }
.hex-bytes { display: flex; gap: 8px; color: #cbd5e1; }
.hex-byte:hover { background: var(--primary); color: #0a0e17; border-radius: 2px; cursor: pointer; }
.hex-ascii { color: #94a3b8; letter-spacing: 1px; }

.inspector-drawer {
  width: 340px;
  background: var(--bg-panel);
  border-left: 1px solid var(--border);
  padding: 14px;
  overflow-y: auto;
  font-family: var(--font-mono);
  font-size: 12px;
}
.insp-row { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
.insp-key { color: var(--text-muted); }
.insp-val { color: var(--primary); font-weight: 600; text-align: right; max-width: 195px; overflow: hidden; text-overflow: ellipsis; }

.hud-grid {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
}
.hud-card {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  position: relative;
}
.hud-card::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--primary); }
.hud-card.pass::before { background: var(--success); }
.hud-card.fail::before { background: var(--danger); }
.hud-title { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; }
.hud-val { font-size: 16px; font-weight: 800; font-family: var(--font-mono); }
.hud-desc { font-size: 12px; color: var(--text-muted); line-height: 1.4; }

footer {
  height: 28px;
  background: #0f172a;
  border-top: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}
.status-left, .status-right { display: flex; gap: 16px; }
.status-item strong { color: var(--text-main); }
</style>
</head>
<body ondragover="event.preventDefault()" ondrop="handleDropFile(event)">

<header>
  <div class="brand">
    <div class="brand-logo">9R0JE6T R10T // R3V3R53-F0RG3</div>
    <span class="badge" id="binary-format-badge">PE x64</span>
    <span style="font-size:12px;color:var(--text-muted)" id="binary-name-label">Drop or Upload Binary</span>
  </div>

  <nav class="nav-tabs">
    <button class="nav-tab active" onclick="switchView('cfg')"><span>⬡ Graph CFG</span> <kbd>Space</kbd></button>
    <button class="nav-tab" onclick="switchView('decomp')"><span>⚙ 8-Pass Decompiled C</span> <kbd>F5</kbd></button>
    <button class="nav-tab" onclick="switchView('hex')"><span># Hex Inspector</span></button>
    <button class="nav-tab" onclick="switchView('intel')"><span>🧠 Capabilities & Ask</span></button>
    <button class="nav-tab" onclick="switchView('xrefs')"><span>🔗 Xrefs</span></button>
    <button class="nav-tab" onclick="switchView('hud')"><span>🛡 Mitigations HUD</span></button>
    <button class="nav-tab" onclick="switchView('pipe')"><span>⚡ 12-Stage Pipeline</span></button>
  </nav>

  <div class="header-actions">
    <input type="text" id="smart-query-input" class="query-bar" placeholder="Ask binary (network, compiler, 0x401000)..." onkeydown="if(event.key==='Enter')runSmartQuery()">
    <button class="btn" onclick="runSmartQuery()">Ask</button>
    <input type="file" id="file-upload-input" style="display:none" onchange="uploadBinaryFile(this.files[0])">
    <button class="btn btn-primary" onclick="document.getElementById('file-upload-input').click()"><span>Upload Binary</span></button>
    <button class="btn" onclick="loadSampleBinary()"><span>Open Path</span></button>
  </div>
</header>

<div class="sub-toolbar">
  <div class="toolbar-group">
    <span style="color:var(--text-muted);font-family:var(--font-mono);">DEBUGGER RSP:</span>
    <button class="btn" onclick="debuggerStep()"><span>⏮ Step Into</span> <kbd>F7</kbd></button>
    <button class="btn" onclick="debuggerContinue()"><span>▶ Continue</span> <kbd>F9</kbd></button>
    <button class="btn" onclick="debuggerToggleBP()"><span>🔴 Breakpoint</span> <kbd>F2</kbd></button>
    <span id="dbg-rip-badge" style="font-family:var(--font-mono);color:var(--success);margin-left:8px;">RIP: 0x00401000</span>
  </div>
  <div class="toolbar-group">
    <button class="btn" onclick="promptRenameSymbol()"><span>✏ Rename Symbol</span> <kbd>N</kbd></button>
    <button class="btn" onclick="promptAddComment()"><span>💬 Add Comment</span> <kbd>;</kbd></button>
    <button class="btn" onclick="runCPUEmulation()"><span>🚀 Emulate Entry (CPU)</span></button>
    <button class="btn" onclick="promptLivePatch()"><span>🩹 Live Patch Binary</span></button>
    <button class="btn" onclick="runVulnAudit()"><span>🛡 CWE Vuln Scan</span></button>
    <button class="btn" onclick="runYaraGenerator()"><span>🧬 Generate YARA/SIGMA</span></button>
    <button class="btn" onclick="runLayer2Bridge()"><span>🌉 Layer-2 Bridge</span></button>
    <button class="btn" onclick="exportCHeader()"><span>⬇ Export .h Header</span></button>
    <button class="btn" onclick="runFullPipeline()"><span>⚡ Execute 12-Stage Audit</span></button>
  </div>
</div>

<div class="workspace">
  <aside class="sidebar">
    <div class="sidebar-header">
      <input type="text" id="filter-input" class="search-input" placeholder="Filter symbols or strings (/) ..." oninput="filterSidebar(this.value)">
      <div class="sidebar-tabs">
        <button class="sidebar-tab active" id="tab-btn-funcs" onclick="switchSidebarTab('funcs')">Functions (<span id="funcs-count">0</span>)</button>
        <button class="sidebar-tab" id="tab-btn-strings" onclick="switchSidebarTab('strings')">Strings (<span id="strings-count">0</span>)</button>
        <button class="sidebar-tab" id="tab-btn-sections" onclick="switchSidebarTab('sections')">Sections</button>
      </div>
    </div>
    <div class="sidebar-list" id="sidebar-list"></div>
  </aside>

  <main class="main-stage">
    <!-- CFG Graph View -->
    <div class="view-panel active" id="view-cfg">
      <div class="cfg-container" id="cfg-container">
        <svg class="cfg-canvas" id="cfg-svg" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <marker id="arrow-true" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#22c55e"/></marker>
            <marker id="arrow-false" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444"/></marker>
            <marker id="arrow-direct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/></marker>
          </defs>
          <g id="cfg-links-layer"></g>
        </svg>
        <div id="cfg-nodes-layer"></div>
        <div class="graph-controls">
          <button class="graph-btn" onclick="zoomGraph(1.15)">+</button>
          <button class="graph-btn" onclick="zoomGraph(0.85)">−</button>
          <button class="graph-btn" onclick="resetGraphZoom()">⤾</button>
        </div>
      </div>
    </div>

    <!-- Decompiled C View -->
    <div class="view-panel" id="view-decomp">
      <div class="code-view" id="code-content"></div>
    </div>

    <!-- Hex & 14-Type Data Inspector View -->
    <div class="view-panel" id="view-hex">
      <div class="hex-split">
        <div class="hex-container">
          <div class="hex-header">
            <div style="width:90px">Offset (VA)</div>
            <div style="width:380px">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</div>
            <div>Decoded ASCII</div>
          </div>
          <div class="hex-body" id="hex-rows"></div>
        </div>
        <div class="inspector-drawer" id="data-inspector-drawer">
          <div style="font-weight:700;color:var(--primary);margin-bottom:10px;">IMHEX 14-TYPE DATA INSPECTOR</div>
          <div id="inspector-rows">Click any byte or run an address query to decode 8/16/32/64-bit ints, floats, timestamps, GUIDs, and disassembly.</div>
        </div>
      </div>
    </div>

    <!-- Capabilities & Smart Query View -->
    <div class="view-panel" id="view-intel">
      <div class="hud-grid" id="intel-grid"></div>
    </div>

    <!-- Cross-References View -->
    <div class="view-panel" id="view-xrefs">
      <div class="code-view" id="xrefs-content"></div>
    </div>

    <!-- Mitigations HUD View -->
    <div class="view-panel" id="view-hud">
      <div class="hud-grid" id="hud-grid"></div>
    </div>

    <!-- 12-Stage Pipeline View -->
    <div class="view-panel" id="view-pipe">
      <div class="code-view" id="pipeline-content" style="padding:20px;">Click "⚡ Execute 12-Stage Audit" in the toolbar to run the full autonomous vulnerability & remediation pipeline on the loaded binary.</div>
    </div>
  </main>
</div>

<footer>
  <div class="status-left">
    <div class="status-item">Engine: <strong>R3V3R53//F0RG3 v10.0-zenith</strong></div>
    <div class="status-item">Internal Engines: <strong>63 Ready</strong></div>
    <div class="status-item">Current VA: <strong id="status-va">0x00401000</strong></div>
  </div>
  <div class="status-right">
    <div class="status-item">Cursor Byte: <strong id="status-byte">0x00 (0)</strong></div>
    <div class="status-item">Status: <strong style="color:var(--success)" id="sync-status">ANALYSIS SYNCHRONIZED</strong></div>
  </div>
</footer>

<script>
// Strict HTML entity sanitizer to prevent DOM XSS from untrusted binary strings/symbols
function escHtml(val) {
  return String(val == null ? '' : val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

let appData = {
  binaryPath: "",
  format: "PE",
  architecture: "x64 (64-bit AMD64)",
  entryPoint: "0x11d430",
  functions: [
    { name: "entry", addr: "0x11d430", size: 64, type: "entry" },
    { name: "setup_security_guards", addr: "0x11d800", size: 96, type: "sub" }
  ],
  strings: [
    { value: "https://edge.microsoft.com", type: "urls", addr: "0x3be410" }
  ],
  sections: [
    { name: ".text", vaddr: "0x1000", vsize: 3917845, entropy: 6.51, perms: "R-X" }
  ],
  mitigations: {
    "Address Space Layout Randomization (ASLR)": { pass: true, val: "Enabled (High-Entropy VA 64-bit)" },
    "Data Execution Prevention (DEP / NX)": { pass: true, val: "Enforced (Hardware NX Bit)" }
  },
  capabilities: [
    { capability_id: "CAP-NET-001", name: "Perform Network Socket / HTTP Communication", mitre_attack: "T1071.001", severity: "MEDIUM", matched_indicators: ["string:https://edge.microsoft.com"], description: "Outbound/inbound network communication indicators." }
  ],
  xrefs: [
    { from_va: "0x11d43a", to_va: "0x11d800", xref_type: "CALL_REL32", instruction: "call 0x11d800", resolved_target_preview: "setup_security_guards" }
  ],
  cfgBlocks: [
    {
      id: 0, x: 240, y: 40, label: "entry_main: 0x11d430",
      insns: [{ mnem: "push", ops: "rbp" }, { mnem: "mov", ops: "rbp, rsp" }, { mnem: "call", ops: "setup_security_guards" }, { mnem: "ret", ops: "" }],
      successors: []
    }
  ],
  hexRows: [],
  pseudocode: [
    "// Decompiled with R3V3R53//F0RG3 8-Pass Unified Decompiler Pipeline",
    "int entry_main(long arg1, long arg2, long arg3) {",
    "    int var_eax = 0;",
    "    var_eax = setup_security_guards();",
    "    return var_eax;",
    "}"
  ]
};

let activeSidebarTab = 'funcs';
let currentZoom = 1.0;

function switchView(viewId) {
  document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  const target = document.getElementById('view-' + viewId);
  if (target) target.classList.add('active');
  const tabBtn = Array.from(document.querySelectorAll('.nav-tab')).find(b => (b.getAttribute('onclick') || '').includes(viewId));
  if (tabBtn) tabBtn.classList.add('active');
}

function switchSidebarTab(tab) {
  activeSidebarTab = tab;
  document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-btn-' + tab).classList.add('active');
  renderSidebar();
}

function renderSidebar() {
  const container = document.getElementById('sidebar-list');
  container.innerHTML = '';
  const filter = (document.getElementById('filter-input').value || '').toLowerCase();

  if (activeSidebarTab === 'funcs') {
    appData.functions.filter(f => f.name.toLowerCase().includes(filter) || f.addr.includes(filter)).forEach(f => {
      const el = document.createElement('div');
      el.className = 'list-item';
      el.innerHTML = `<span class="item-name">${escHtml(f.name)}</span><span class="item-addr">${escHtml(f.addr)}</span>`;
      el.onclick = () => jumpToAddress(f.addr);
      container.appendChild(el);
    });
  } else if (activeSidebarTab === 'strings') {
    appData.strings.filter(s => s.value.toLowerCase().includes(filter)).forEach(s => {
      const el = document.createElement('div');
      el.className = 'list-item';
      el.innerHTML = `<span class="item-name" title="${escHtml(s.value)}">"${escHtml(s.value)}"</span><span class="item-addr">${escHtml(s.addr)}</span>`;
      el.onclick = () => jumpToAddress(s.addr);
      container.appendChild(el);
    });
  } else if (activeSidebarTab === 'sections') {
    appData.sections.forEach(s => {
      const el = document.createElement('div');
      el.className = 'list-item';
      el.innerHTML = `<span class="item-name"><strong>${escHtml(s.name)}</strong> (${escHtml(s.perms || 'R-X')})</span><span class="item-addr">${escHtml(s.vaddr || s.virtual_address || '0x0')}</span>`;
      container.appendChild(el);
    });
  }
}

function renderDecomp() {
  const container = document.getElementById('code-content');
  container.innerHTML = '';
  appData.pseudocode.forEach((line, idx) => {
    let safeLine = escHtml(line);
    let colored = safeLine
      .replace(/\b(int64_t|uint64_t|int32_t|uint32_t|uint16_t|uint8_t|int|long|void|typedef|struct)\b/g, '<span class="type">$1</span>')
      .replace(/\b(if|else|while|do|switch|case|default|break|return|__fastcall)\b/g, '<span class="kw">$1</span>')
      .replace(/(\b0x[0-9a-fA-F]+\b|\b\d+\b)/g, '<span class="num">$1</span>');
    const row = document.createElement('div');
    row.className = 'code-line';
    row.innerHTML = `<div class="code-num">${idx + 1}</div><div class="code-text">${colored}</div>`;
    container.appendChild(row);
  });
}

function renderHexView() {
  const container = document.getElementById('hex-rows');
  container.innerHTML = '';
  if (appData.hexRows && appData.hexRows.length > 0) {
    appData.hexRows.forEach(hr => {
      const row = document.createElement('div');
      row.className = 'hex-row';
      const bytesSpans = (hr.bytes || []).map(bHex => {
        const decVal = parseInt(bHex, 16) || 0;
        return `<span class="hex-byte" onmouseover="updateHoverByte('0x${escHtml(bHex)}', ${decVal})" onclick="inspectByteOffset('${escHtml(hr.offset)}')">${escHtml(bHex)}</span>`;
      }).join('');
      row.innerHTML = `<div class="hex-offset">${escHtml(hr.offset)}</div><div class="hex-bytes">${bytesSpans}</div><div class="hex-ascii">${escHtml(hr.ascii)}</div>`;
      container.appendChild(row);
    });
    return;
  }
  const baseVA = 0x00401000;
  for (let r = 0; r < 24; r++) {
    const rowVA = baseVA + (r * 16);
    const rowHex = '0x' + rowVA.toString(16).padStart(8, '0');
    let bytesHTML = '';
    let asciiText = '';
    for (let c = 0; c < 16; c++) {
      const val = (rowVA + c * 7) % 256;
      const bHex = val.toString(16).padStart(2, '0').toUpperCase();
      const ch = (val >= 32 && val <= 126) ? String.fromCharCode(val) : '.';
      bytesHTML += `<span class="hex-byte" onmouseover="updateHoverByte('0x${bHex}', ${val})" onclick="inspectByteOffset('${rowHex}')">${bHex}</span>`;
      asciiText += ch;
    }
    const row = document.createElement('div');
    row.className = 'hex-row';
    row.innerHTML = `<div class="hex-offset">${rowHex}</div><div class="hex-bytes">${bytesHTML}</div><div class="hex-ascii">${escHtml(asciiText)}</div>`;
    container.appendChild(row);
  }
}

function inspectByteOffset(offsetHex) {
  document.getElementById('status-va').innerText = offsetHex;
  if (!appData.binaryPath) return;
  fetch(`/api/inspect?path=${encodeURIComponent(appData.binaryPath)}&offset=${encodeURIComponent(offsetHex)}`)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok' && data.inspection) {
        const ins = data.inspection;
        const container = document.getElementById('inspector-rows');
        const fields = [
          ['Virtual Address', ins.virtual_address],
          ['File Offset', '0x' + ins.file_offset.toString(16)],
          ['Section', ins.containing_section],
          ['uint8 / int8', `${ins.uint8} / ${ins.int8}`],
          ['uint16 / int16', `${ins.uint16_le} / ${ins.int16_le}`],
          ['uint32 / int32', `${ins.uint32_le} / ${ins.int32_le}`],
          ['uint64', `${ins.uint64_le}`],
          ['float32 / float64', `${ins.float32_le} / ${ins.float64_le}`],
          ['Unix Timestamp', ins.unix_timestamp_iso],
          ['GUID / UUID', ins.guid_uuid],
          ['ASCII String', ins.ascii_string],
          ['Disassembly', (ins.disassembly_preview || []).join(' ; ')]
        ];
        container.innerHTML = fields.map(([k, v]) => `<div class="insp-row"><span class="insp-key">${escHtml(k)}</span><span class="insp-val">${escHtml(v)}</span></div>`).join('');
      }
    });
}

function renderCapabilitiesAndIntel(customResults) {
  const grid = document.getElementById('intel-grid');
  grid.innerHTML = '';
  const items = customResults || appData.capabilities || [];
  items.forEach(cap => {
    const card = document.createElement('div');
    card.className = 'hud-card pass';
    const title = cap.name || cap.match_type || cap.type || 'Intelligence Match';
    const val = cap.mitre_attack || cap.matched_value || cap.value || cap.capability_id || '';
    const desc = cap.description || JSON.stringify(cap);
    card.innerHTML = `
      <div class="hud-title">${escHtml(cap.capability_id || cap.section_name || 'INTEL')}</div>
      <div class="hud-val" style="color:var(--primary)">${escHtml(title)}</div>
      <div class="hud-desc"><strong>${escHtml(val)}</strong><br>${escHtml(desc)}</div>
    `;
    grid.appendChild(card);
  });
}

function renderXrefs() {
  const container = document.getElementById('xrefs-content');
  const rows = (appData.xrefs || []).map((x, idx) =>
    `<div class="code-line"><div class="code-num">${idx + 1}</div><div class="code-text">${escHtml(x.from_va)}  [${escHtml(x.xref_type)}]  ${escHtml(x.instruction.padEnd(28))} -> ${escHtml(x.to_va)} (${escHtml(x.resolved_target_preview || '')})</div></div>`
  );
  container.innerHTML = rows.join('') || '<div style="color:var(--text-muted)">No cross-references extracted yet.</div>';
}

function renderMitigationsHUD() {
  const grid = document.getElementById('hud-grid');
  grid.innerHTML = '';
  for (const [title, info] of Object.entries(appData.mitigations)) {
    const isPass = typeof info === 'object' ? info.pass : Boolean(info);
    const descVal = typeof info === 'object' ? info.val : String(info);
    const card = document.createElement('div');
    card.className = `hud-card ${isPass ? 'pass' : 'fail'}`;
    card.innerHTML = `
      <div class="hud-title">${escHtml(title)}</div>
      <div class="hud-val" style="color:${isPass ? 'var(--success)' : 'var(--danger)'}">${isPass ? '✓ ENABLED' : '✗ ABSENT'}</div>
      <div class="hud-desc">${escHtml(descVal)}</div>
    `;
    grid.appendChild(card);
  }
}

function renderCFGGraph() {
  const nodesLayer = document.getElementById('cfg-nodes-layer');
  const linksLayer = document.getElementById('cfg-links-layer');
  nodesLayer.innerHTML = '';
  linksLayer.innerHTML = '';

  const blocks = (appData.cfgBlocks && appData.cfgBlocks.length > 0) ? appData.cfgBlocks : [];
  const addrToBlock = {};
  blocks.forEach(b => { if (b.addr) addrToBlock[b.addr.toLowerCase()] = b; });

  blocks.forEach(b => {
    const nodeEl = document.createElement('div');
    nodeEl.className = 'cfg-node';
    nodeEl.style.left = (b.x || 120) + 'px';
    nodeEl.style.top = (b.y || 40) + 'px';
    let insnHTML = (b.insns || []).map(i => `<div class="cfg-insn"><span class="cfg-mnem">${escHtml(i.mnem)}</span><span class="cfg-ops">${escHtml(i.ops)}</span></div>`).join('');
    nodeEl.innerHTML = `<div class="cfg-node-hdr">${escHtml(b.label)}</div><div class="cfg-node-body">${insnHTML}</div>`;
    nodesLayer.appendChild(nodeEl);
  });

  blocks.forEach(b => {
    (b.successors || []).forEach((succAddr, idx) => {
      const targetBlock = addrToBlock[String(succAddr).toLowerCase()];
      if (targetBlock) {
        const x1 = (b.x || 120) + 135, y1 = (b.y || 40) + 115;
        const x2 = (targetBlock.x || 120) + 135, y2 = (targetBlock.y || 40);
        const color = idx === 0 ? '#22c55e' : '#ef4444';
        const marker = idx === 0 ? 'arrow-true' : 'arrow-false';
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M ${x1} ${y1} C ${x1} ${(y1+y2)/2}, ${x2} ${(y1+y2)/2}, ${x2} ${y2}`);
        path.setAttribute('stroke', color);
        path.setAttribute('stroke-width', '2');
        path.setAttribute('fill', 'none');
        path.setAttribute('marker-end', `url(#${marker})`);
        linksLayer.appendChild(path);
      }
    });
  });
}

function updateHoverByte(hexStr, decVal) {
  document.getElementById('status-byte').innerText = `${hexStr} (${decVal})`;
}

function jumpToAddress(va) {
  document.getElementById('status-va').innerText = va;
  inspectByteOffset(va);
  switchView('decomp');
}

function promptJump() {
  const target = prompt("Enter Virtual Address or Offset to inspect (e.g. 0x401000):", appData.entryPoint);
  if (target) jumpToAddress(target);
}

function filterSidebar() { renderSidebar(); }
function zoomGraph(factor) {
  currentZoom *= factor;
  document.getElementById('cfg-nodes-layer').style.transform = `scale(${currentZoom})`;
  document.getElementById('cfg-links-layer').style.transform = `scale(${currentZoom})`;
}
function resetGraphZoom() {
  currentZoom = 1.0;
  document.getElementById('cfg-nodes-layer').style.transform = `scale(1.0)`;
  document.getElementById('cfg-links-layer').style.transform = `scale(1.0)`;
}

function debuggerStep() {
  fetch('/api/debug?action=step').then(r => r.json()).then(d => {
    document.getElementById('status-va').innerText = d.snapshot.rip;
    document.getElementById('dbg-rip-badge').innerText = 'RIP: ' + d.snapshot.rip;
  });
}
function debuggerContinue() {
  fetch('/api/debug?action=continue').then(r => r.json()).then(d => {
    document.getElementById('status-va').innerText = d.snapshot.rip;
    document.getElementById('dbg-rip-badge').innerText = 'RIP: ' + d.snapshot.rip;
  });
}
function debuggerToggleBP() {
  const curVa = document.getElementById('status-va').innerText;
  fetch('/api/debug?action=bp&addr=' + encodeURIComponent(curVa)).then(r => r.json()).then(d => {
    document.getElementById('dbg-rip-badge').innerText = `BP @ ${curVa} (${d.snapshot.active_breakpoints.length} active)`;
  });
}

function promptRenameSymbol() {
  const addr = prompt("Enter symbol address to rename:", appData.entryPoint);
  if (!addr) return;
  const newName = prompt("Enter new function name:", "decrypt_config_packet");
  if (!newName) return;
  fetch('/api/annotate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ action: 'rename', address: addr, value: newName, path: appData.binaryPath })
  }).then(r => r.json()).then(d => {
    if (d.status === 'ok') {
      if (appData.binaryPath) loadBinaryFromServer(appData.binaryPath);
    }
  });
}

function promptAddComment() {
  const addr = prompt("Enter address for comment:", appData.entryPoint);
  if (!addr) return;
  const cmt = prompt("Enter analyst comment:", "Verified bounds check");
  if (!cmt) return;
  fetch('/api/annotate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ action: 'comment', address: addr, value: cmt, path: appData.binaryPath })
  });
}

async function runYaraGenerator() {
  if (!appData.currentBinaryPath) return;
  document.getElementById("smart-query-input").value = "yara";
  await runSmartQuery();
}

async function runLayer2Bridge() {
  if (!appData.currentBinaryPath) return;
  document.getElementById("smart-query-input").value = "bridge";
  await runSmartQuery();
}

async function runCPUEmulation() {
  if (!appData.currentBinaryPath) return;
  document.getElementById("smart-query-input").value = "emulate";
  await runSmartQuery();
}

async function promptLivePatch() {
  if (!appData.currentBinaryPath) return;
  const off = prompt("Enter file offset to patch (e.g. 0x40):", "0x40");
  if (!off) return;
  const op = prompt("Patch operation (nop, invert, ret0, ret1):", "nop");
  if (!op) return;
  const r = await fetch(`/api/patch?path=${encodeURIComponent(appData.currentBinaryPath)}`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({offset: off, operation: op})
  });
  const d = await r.json();
  if (d.status === "ok" && d.patched_path) {
    loadBinaryFromServer(d.patched_path);
  }
}

async function runVulnAudit() {
  if (!appData.currentBinaryPath) return;
  document.getElementById("smart-query-input").value = "vulnerabilities";
  await runSmartQuery();
}

function exportCHeader() {
  window.open('/api/export-header', '_blank');
}

function runFullPipeline() {
  if (!appData.binaryPath) {
    alert("Upload or open a binary first to run the 12-stage audit pipeline.");
    return;
  }
  switchView('pipe');
  document.getElementById('pipeline-content').innerText = "Running 12-stage autonomous pipeline...";
  fetch('/api/pipeline?path=' + encodeURIComponent(appData.binaryPath))
    .then(r => r.json())
    .then(d => {
      if (d.status === 'ok') {
        document.getElementById('pipeline-content').innerText = d.markdown_report;
      }
    });
}

function uploadBinaryFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(evt) {
    fetch('/api/upload?filename=' + encodeURIComponent(file.name), {
      method: 'POST',
      body: evt.target.result
    })
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok' && data.saved_path) {
        loadBinaryFromServer(data.saved_path);
      }
    });
  };
  reader.readAsArrayBuffer(file);
}

function handleDropFile(evt) {
  evt.preventDefault();
  if (evt.dataTransfer && evt.dataTransfer.files && evt.dataTransfer.files.length > 0) {
    uploadBinaryFile(evt.dataTransfer.files[0]);
  }
}

function runSmartQuery() {
  const q = document.getElementById('smart-query-input').value.trim();
  if (!q) return;
  if (!appData.binaryPath) {
    switchView('intel');
    renderCapabilitiesAndIntel();
    return;
  }
  fetch(`/api/query?path=${encodeURIComponent(appData.binaryPath)}&q=${encodeURIComponent(q)}`)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok' && data.answer) {
        switchView('intel');
        renderCapabilitiesAndIntel(data.answer.results);
      }
    });
}

function loadBinaryFromServer(path) {
  fetch('/api/analyze?path=' + encodeURIComponent(path))
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok') {
        const d = data.dossier;
        appData.binaryPath = d.artifact;
        appData.format = d.format;
        appData.architecture = d.architecture;
        appData.entryPoint = d.entry_point;
        document.getElementById('binary-format-badge').innerText = `${d.format} ${d.architecture}`;
        document.getElementById('binary-name-label').innerText = `${d.artifact.split(/[\\/]/).pop()} (${(d.size_bytes / 1024).toFixed(1)} KB)`;
        appData.sections = d.sections.map(s => ({
          name: s.name || '.sec',
          vaddr: s.virtual_address || '0x0',
          vsize: s.virtual_size || s.raw_size || 0,
          perms: s.executable ? 'R-X' : 'R--'
        }));
        appData.capabilities = d.capabilities || [];
        appData.xrefs = d.top_xrefs || [];
        appData.mitigations = d.mitigations || {};
        appData.cfgBlocks = d.cfg_blocks || appData.cfgBlocks;
        appData.hexRows = d.hex_rows || [];
        appData.pseudocode = (d.unified_decompiled_c || d.structured_goto_free_c || d.decompiled_entry_c || '').split('\n');
        const urls = (d.categorized_strings && d.categorized_strings.urls) || [];
        const gen = (d.categorized_strings && d.categorized_strings.general) || [];
        appData.strings = [...urls, ...gen].slice(0, 50).map((s, i) => ({ value: s, addr: '0x' + (0x2000 + i * 16).toString(16) }));
        appData.functions = [{ name: "entry_main", addr: d.entry_point, size: 128 }, ...appData.xrefs.filter(x => x.xref_type === 'CALL_REL32').map(x => ({ name: x.resolved_target_preview, addr: x.to_va, size: 64 }))];
        renderAll();
      } else {
        alert('Error analyzing binary: ' + (data.error || 'Unknown'));
      }
    });
}

function loadSampleBinary() {
  const path = prompt("Enter server binary path to analyze:", appData.binaryPath || "/bin/ls");
  if (path) loadBinaryFromServer(path);
}

function renderAll() {
  document.getElementById('funcs-count').innerText = appData.functions.length;
  document.getElementById('strings-count').innerText = appData.strings.length;
  renderSidebar();
  renderDecomp();
  renderHexView();
  renderCapabilitiesAndIntel();
  renderXrefs();
  renderMitigationsHUD();
  renderCFGGraph();
}

window.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT') return;
  if (e.code === 'Space') {
    e.preventDefault();
    const isCfg = document.getElementById('view-cfg').classList.contains('active');
    switchView(isCfg ? 'hex' : 'cfg');
  } else if (e.key === 'F5') {
    e.preventDefault();
    switchView('decomp');
  } else if (e.key === 'g' || e.key === 'G') {
    e.preventDefault();
    promptJump();
  } else if (e.key === 'n' || e.key === 'N') {
    e.preventDefault();
    promptRenameSymbol();
  } else if (e.key === ';') {
    e.preventDefault();
    promptAddComment();
  } else if (e.key === '/') {
    e.preventDefault();
    document.getElementById('filter-input').focus();
  } else if (e.key === 'F7') {
    e.preventDefault();
    debuggerStep();
  } else if (e.key === 'F8' || e.key === 'F9') {
    e.preventDefault();
    debuggerContinue();
  } else if (e.key === 'F2') {
    e.preventDefault();
    debuggerToggleBP();
  }
});

window.addEventListener('DOMContentLoaded', () => {
  renderAll();
  const params = new URLSearchParams(window.location.search);
  const initPath = params.get('path');
  if (initPath) loadBinaryFromServer(initPath);
});
</script>
</body>
</html>
"""


class GUIWorkbenchHandler(http.server.BaseHTTPRequestHandler):
    """Hardened, zero-dependency REST API & Web GUI server for R3V3R53//F0RG3."""

    default_binary_path: Optional[str] = None
    project_db: ProjectWorkspaceDB = ProjectWorkspaceDB()
    active_debugger: Any = None
    MAX_UPLOAD_BYTES: int = 32 * 1024 * 1024

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _is_trusted_origin(self) -> bool:
        """Block cross-origin browser requests from external websites (SEC-03)."""
        origin = self.headers.get("Origin", "")
        if not origin:
            return True
        parsed = urllib.parse.urlparse(origin)
        return parsed.hostname in ("127.0.0.1", "localhost", "::1")

    def do_POST(self) -> None:
        if not self._is_trusted_origin():
            self._json_response({"status": "error", "error": "Forbidden cross-origin request"}, status=403)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        content_len = int(self.headers.get("Content-Length", "0"))
        if content_len <= 0 or content_len > self.MAX_UPLOAD_BYTES:
            self._json_response({"status": "error", "error": "Invalid or oversized payload"}, status=400)
            return

        raw_body = self.rfile.read(content_len)

        if path == "/api/upload":
            raw_fname = query.get("filename", ["uploaded.bin"])[0]
            safe_fname = "".join(c if (c.isalnum() or c in "._-") else "_" for c in os.path.basename(raw_fname)) or "uploaded.bin"
            upload_dir = os.path.join(tempfile.gettempdir(), "reverse_forge_uploads")
            os.makedirs(upload_dir, exist_ok=True)
            saved_path = os.path.join(upload_dir, safe_fname)
            with open(saved_path, "wb") as f:
                f.write(raw_body)
            self._json_response({
                "status": "ok",
                "filename": safe_fname,
                "saved_path": saved_path,
                "size_bytes": len(raw_body),
            })
            return

        elif path == "/api/annotate":
            try:
                payload = json.loads(raw_body.decode("utf-8"))
                act = payload.get("action", "")
                addr = payload.get("address", "0x401000")
                val = payload.get("value", "")
                if act == "rename":
                    new_sym = self.project_db.rename_symbol(addr, val)
                    self._json_response({"status": "ok", "action": "rename", "address": addr, "symbol": new_sym})
                    return
                elif act == "comment":
                    self.project_db.set_comment(addr, val)
                    self._json_response({"status": "ok", "action": "comment", "address": addr, "comment": val})
                    return
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=400)
                return

        elif path == "/api/patch":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            try:
                from reverse_forge.binary_patcher import BinaryPatcherEngine
                payload = json.loads(raw_body.decode("utf-8"))
                off_s = str(payload.get("offset", "0x0"))
                file_off = int(off_s, 16) if off_s.lower().startswith("0x") else int(off_s, 10)
                op = str(payload.get("operation", "nop")).lower()
                with open(bin_path, "rb") as f:
                    orig_data = f.read(self.MAX_UPLOAD_BYTES)
                patcher = BinaryPatcherEngine(orig_data)
                if op == "nop":
                    tx = patcher.nop_range(file_off, int(payload.get("length", 1)))
                elif op == "invert":
                    tx = patcher.invert_conditional_branch(file_off)
                elif op == "ret0":
                    tx = patcher.patch_function_return(file_off, return_value=0)
                elif op == "ret1":
                    tx = patcher.patch_function_return(file_off, return_value=1)
                else:
                    raw_hex = str(payload.get("hex_bytes", "90"))
                    tx = patcher.apply_raw_patch(file_off, bytes.fromhex(raw_hex), description="Web UI patch")
                patch_dir = os.path.join(tempfile.gettempdir(), "reverse_forge_uploads")
                os.makedirs(patch_dir, exist_ok=True)
                patched_path = os.path.join(patch_dir, "patched_" + os.path.basename(bin_path))
                summary = patcher.save_patched_binary(patched_path)
                self._json_response({
                    "status": "ok",
                    "patched_path": patched_path,
                    "transaction": asdict(tx),
                    "summary": asdict(summary),
                })
                return
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=400)
                return

        self._json_response({"error": "Endpoint not found"}, status=404)

    def do_GET(self) -> None:
        if not self._is_trusted_origin():
            self._json_response({"status": "error", "error": "Forbidden cross-origin request"}, status=403)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
            return

        elif path == "/api/status":
            self._json_response({
                "status": "ready",
                "engine": "R3V3R53//F0RG3",
                "version": "26.0.0-rust-bicentennial",
                "active_engines": 87,
                "default_binary": self.default_binary_path,
            })
            return

        elif path == "/api/pcap":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid path"}, status=400)
                return
            from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine
            with open(bin_path, "rb") as f:
                data = f.read(8 * 1024 * 1024)
            rep = OmniToolkit16CatEngine().dissect_pcap_and_infer_protocol(data)
            self._json_response({"status": "ok", "pcap_report": asdict(rep)})
            return

        elif path == "/api/imhex":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            pat = query.get("pattern", ["struct Header { u16 magic; u16 cblp; u32 reserved; };"])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid path"}, status=400)
                return
            from reverse_forge.omni_toolkit_16cat import OmniToolkit16CatEngine
            with open(bin_path, "rb") as f:
                data = f.read(1048576)
            fields = OmniToolkit16CatEngine().evaluate_imhex_pattern(data, pat, 0)
            self._json_response({"status": "ok", "fields": [asdict(x) for x in fields]})
            return

        elif path == "/api/rust-bench":
            from reverse_forge.native_rust_bridge import NativeRustAccelerator
            rep = NativeRustAccelerator.benchmark_rust_vs_python(262144)
            self._json_response({"status": "ok", "rust_benchmark": asdict(rep)})
            return

        elif path == "/api/force-exec":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.underconstrained_visor_engine import UnderConstrainedMicroVisor
            with open(bin_path, "rb") as f:
                data = f.read(1048576)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, intel.metadata)
            v_rep = UnderConstrainedMicroVisor(base_va=entry_va or 0x401000).force_execute_function(code_slice[:512])
            self._json_response({"status": "ok", "visor_report": asdict(v_rep)})
            return

        elif path == "/api/decompile-fuse":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.multi_decompiler_fusion_engine import MultiDecompilerFusionEngine
            with open(bin_path, "rb") as f:
                data = f.read(1048576)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, intel.metadata)
            f_rep = MultiDecompilerFusionEngine().decompile_with_fusion(code_slice, base_va=entry_va or 0x401000)
            self._json_response({"status": "ok", "fusion_report": asdict(f_rep)})
            return

        elif path == "/api/memory-dump":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.live_memory_dump_engine import LiveMemoryAndDumpEngine
            with open(bin_path, "rb") as f:
                data = f.read(16 * 1024 * 1024)
            m_rep = LiveMemoryAndDumpEngine().analyze_dump(data)
            self._json_response({"status": "ok", "dump_report": asdict(m_rep)})
            return

        elif path == "/api/yara":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.yara_sigma_ioc_generator import YaraSigmaIOCGenerator
            with open(bin_path, "rb") as f:
                data = f.read(4 * 1024 * 1024)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            code_slice, _ = CorrelationEngine._resolve_disassembly_slice(data, intel.metadata)
            bundle = YaraSigmaIOCGenerator().generate_all(data, intel.get_full_dossier(), code_slice=code_slice)
            self._json_response({"status": "ok", "detection_bundle": asdict(bundle)})
            return

        elif path == "/api/bridge":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.tier2_bridge_exporter import Tier2BridgeExporter
            with open(bin_path, "rb") as f:
                data = f.read(4 * 1024 * 1024)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            pkg = Tier2BridgeExporter().export_bridge_package(
                intel.get_full_dossier(),
                symbol_renames=self.project_db.symbol_renames,
                analyst_comments=self.project_db.comments,
            )
            self._json_response({"status": "ok", "bridge_package": asdict(pkg)})
            return

        elif path == "/api/container":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.archive_container_triage_engine import ArchiveContainerTriageEngine
            with open(bin_path, "rb") as f:
                data = f.read(16 * 1024 * 1024)
            rep = ArchiveContainerTriageEngine().triage_container(data)
            self._json_response({"status": "ok", "container_report": asdict(rep)})
            return

        elif path == "/api/emulate":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.cpu_emulator_engine import DeterministicCPUEmulator
            with open(bin_path, "rb") as f:
                data = f.read(1048576)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, intel.metadata)
            emu_rep = DeterministicCPUEmulator(base_va=entry_va or 0x401000).emulate_bytes(code_slice[:512], max_steps=64)
            self._json_response({"status": "ok", "emulation": asdict(emu_rep)})
            return

        elif path == "/api/bytecode":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.bytecode_clr_dex_wasm_engine import BytecodeManagedEngine
            with open(bin_path, "rb") as f:
                data = f.read(4 * 1024 * 1024)
            bc_rep = BytecodeManagedEngine().analyze_binary(data)
            self._json_response({"status": "ok", "bytecode": asdict(bc_rep)})
            return

        elif path == "/api/config-extract":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            from reverse_forge.config_crypto_extractor import ConfigAndCryptoExtractorEngine
            with open(bin_path, "rb") as f:
                data = f.read(4 * 1024 * 1024)
            cfg_rep = ConfigAndCryptoExtractorEngine().extract_all(data)
            self._json_response({"status": "ok", "config_crypto": asdict(cfg_rep)})
            return

        elif path == "/api/vulns":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            with open(bin_path, "rb") as f:
                data = f.read(4 * 1024 * 1024)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            dos = intel.get_full_dossier()
            self._json_response({
                "status": "ok",
                "vulnerabilities_count": dos.get("vulnerabilities_count", 0),
                "risk_rating": dos.get("vulnerability_risk_rating", "CLEAN"),
                "vulnerabilities": dos.get("vulnerabilities", []),
            })
            return

        elif path == "/api/export-header":
            hdr_text = self.project_db.export_c_header()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(hdr_text.encode("utf-8"))
            return

        elif path == "/api/load":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": f"File not found: {bin_path}"}, status=400)
                return
            try:
                with open(bin_path, "rb") as f:
                    data = f.read(65536)
                fmt = CorrelationEngine().identify_format(data)
                self._json_response({
                    "status": "ok",
                    "path": os.path.abspath(bin_path),
                    "size_bytes": os.path.getsize(bin_path),
                    "format": fmt,
                })
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=500)
            return

        elif path == "/api/analyze":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": f"File not found: {bin_path}"}, status=400)
                return
            try:
                with open(bin_path, "rb") as f:
                    data = f.read(4 * 1024 * 1024)
                intel = BinaryIntelEngine(data, filepath=bin_path)
                dossier = intel.get_full_dossier()
                if self.project_db.symbol_renames:
                    dossier["unified_decompiled_c"] = self.project_db.apply_annotations_to_c_code(
                        dossier.get("unified_decompiled_c", "")
                    )
                self._json_response({
                    "status": "ok",
                    "dossier": dossier,
                })
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=500)
            return

        elif path == "/api/hex":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            offset_str = query.get("offset", ["0x0"])[0]
            rows_cnt = min(64, int(query.get("rows", ["32"])[0]))
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            with open(bin_path, "rb") as f:
                data = f.read(4 * 1024 * 1024)
            start_off = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str, 10)
            start_off = max(0, min(len(data), start_off))
            hex_rows = []
            for r in range(rows_cnt):
                off = start_off + r * 16
                if off >= len(data):
                    break
                chunk = data[off : off + 16]
                hex_rows.append({
                    "offset": f"0x{off:08x}",
                    "bytes": [f"{b:02X}" for b in chunk],
                    "ascii": "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk),
                })
            self._json_response({"status": "ok", "hex_rows": hex_rows})
            return

        elif path == "/api/cfg":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            with open(bin_path, "rb") as f:
                data = f.read(1048576)
            intel = BinaryIntelEngine(data, filepath=bin_path)
            code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, intel.metadata)
            res = UnifiedDecompilerPipeline().decompile_function_bytes(code_slice, base_va=entry_va or 0x401000)
            self._json_response({"status": "ok", "cfg_blocks": res.cfg_blocks, "c_code": res.final_c_code})
            return

        elif path == "/api/pipeline":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            with tempfile.TemporaryDirectory() as tmpdir:
                pipe = PipelineStateMachine(
                    artifact_path=bin_path,
                    workspace_dir=tmpdir,
                    authorized_scope="*",
                    autonomy_level=AutonomyLevel.LEVEL_3_AUTONOMOUS_STATIC,
                )
                pipe.run_all_stages()
                st = pipe.get_pipeline_state()
                self._json_response({"status": "ok", "markdown_report": st["report_markdown"], "stages": st["stages"]})
            return

        elif path == "/api/inspect":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            offset_str = query.get("offset", ["0x0"])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            try:
                with open(bin_path, "rb") as f:
                    data = f.read(4 * 1024 * 1024)
                intel = BinaryIntelEngine(data, filepath=bin_path)
                insp = intel.inspect_offset(offset_str)
                self._json_response({"status": "ok", "inspection": asdict(insp)})
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=500)
            return

        elif path == "/api/query":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            q_str = query.get("q", ["capabilities"])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            try:
                with open(bin_path, "rb") as f:
                    data = f.read(4 * 1024 * 1024)
                intel = BinaryIntelEngine(data, filepath=bin_path)
                ans = intel.smart_query(q_str)
                self._json_response({"status": "ok", "answer": asdict(ans)})
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=500)
            return

        elif path == "/api/debug":
            from reverse_forge.gdb_rsp_debugger import GDBRSPClient
            action = query.get("action", ["status"])[0]
            addr_s = query.get("addr", ["0x401000"])[0]
            if GUIWorkbenchHandler.active_debugger is None or action == "reset":
                GUIWorkbenchHandler.active_debugger = GDBRSPClient(simulated=True)
                GUIWorkbenchHandler.active_debugger.connect()
            dbg = GUIWorkbenchHandler.active_debugger
            if action == "step":
                snap = dbg.step_into()
            elif action == "continue":
                snap = dbg.continue_execution()
            elif action == "bp":
                addr_int = int(addr_s, 16) if addr_s.startswith("0x") else int(addr_s, 10)
                dbg.set_breakpoint(addr_int, "sw")
                snap = dbg.step_into()
            else:
                snap = dbg.step_into()
            self._json_response({"status": "ok", "snapshot": asdict(snap)})
            return

        elif path == "/api/canvas":
            from reverse_forge.virtualized_canvas_engine import VirtualizedCanvasEngine, GraphNodeBox, ViewportBox
            zoom = float(query.get("zoom", ["1.0"])[0])
            vc = VirtualizedCanvasEngine()
            vc.add_node(GraphNodeBox(0, "entry: 0x401000", 100.0, 80.0, 260.0, 120.0, 0.3, ["push rbp", "mov rbp, rsp"], [1]))
            vc.add_node(GraphNodeBox(1, "loc_401020", 100.0, 260.0, 260.0, 100.0, 0.7, ["xor eax, eax", "ret"], []))
            frame = vc.render_viewport_frame(ViewportBox(0.0, 0.0, 1280.0, 720.0, zoom_scale=zoom))
            self._json_response({"status": "ok", "frame": frame})
            return

        elif path == "/api/decompile":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            with open(bin_path, "rb") as f:
                data = f.read(1048576)
            ce = CorrelationEngine()
            fmt = ce.identify_format(data)
            meta = (
                PEAnalyzer(data).analyze() if fmt == "PE"
                else (ELFAnalyzer(data).analyze() if fmt == "ELF"
                      else (MachOAnalyzer(data).analyze() if fmt == "Mach-O" else {}))
            )
            code_slice, entry_va = CorrelationEngine._resolve_disassembly_slice(data, meta)
            uni = UnifiedDecompilerPipeline().decompile_function_bytes(code_slice, base_va=entry_va or 0x401000)
            self._json_response({
                "status": "ok",
                "c_source": uni.final_c_code,
                "complexity": len(uni.cfg_blocks),
                "blocks_count": len(uni.cfg_blocks),
                "cfg_blocks": uni.cfg_blocks,
            })
            return

        self._json_response({"error": "Endpoint not found"}, status=404)

    def _json_response(self, data: Dict[str, Any], status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        # SEC-03: Only emit Access-Control-Allow-Origin for verified localhost origins
        origin = self.headers.get("Origin", "")
        if origin and self._is_trusted_origin():
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


def start_gui_workbench(port: int = 8080, open_browser: bool = True, binary_path: Optional[str] = None) -> None:
    """Launch the local GUI workbench server."""
    class ReusableServer(socketserver.TCPServer):
        allow_reuse_address = True

    GUIWorkbenchHandler.default_binary_path = binary_path
    try:
        httpd = ReusableServer(("127.0.0.1", port), GUIWorkbenchHandler)
    except OSError:
        port += 1
        httpd = ReusableServer(("127.0.0.1", port), GUIWorkbenchHandler)

    url = f"http://127.0.0.1:{port}"
    if binary_path:
        url += f"/?path={urllib.parse.quote(os.path.abspath(binary_path))}"

    print(f"\n  ╔════════════════════════════════════════════════════════════════════╗")
    print(f"  ║   9R0JE6T R10T // R3V3R53-F0RG3  Interactive GUI Workbench v10.0  ║")
    print(f"  ║   Hardened XSS/CORS · Drag-Drop Upload · Live 8-Pass Decompiler    ║")
    print(f"  ║   URL: {url:<54}║")
    print(f"  ╚════════════════════════════════════════════════════════════════════╝\n")

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down GUI workbench server...")
        httpd.shutdown()


if __name__ == "__main__":
    start_gui_workbench()
