"""
R3V3R53//F0RG3 — Synchronized 4-Pane Multi-Dock Reverse-Engineering Workbench (`gui_server.py`)
===============================================================================================
v27.0.0 Studio & Functional Overhaul:
  - True 4-Pane Synchronized Split IDE (like Binary Ninja / Cutter / Ghidra):
    1. Left Dock: Whole-Binary Function Browser (discovers `_start` -> `main`, all internal `sub_xxxx`
       CALL targets, and all `.rela.plt`/`.dynsym`/IAT imports), Strings, and Sections.
    2. Center-Left Pane: Interactive Pan/Zoom Sugiyama Control-Flow Graph (`Graph CFG`) +
       Linear Disassembly table with inline string literal & symbol comments.
    3. Center-Right Pane (Side-by-Side Synchronized): Live Decompiler & Multi-IR Inspector
       (`Decompiled C` | `Ghidra P-Code SSA` | `Rizin ESIL` | `angr VEX IRSB`) with bidirectional
       address highlighting (`// @ 0x...` <-> CFG/Disassembly <-> Hex Inspector).
    4. Bottom Dock: Synchronized Hex Editor + 14-Format ImHex Data Inspector + Mitigations HUD +
       Interactive Analysis & Native Rust Engine Console (`55` Rust modules / `54` CLI commands).
  - Zero `window.prompt()` / `window.alert()` popups: All actions (`Rename Symbol [N]`,
    `Add Comment [;]`, `Jump to Address [G]`, `Live Patch`, `Open Server Path`) use an in-app
    non-blocking Command Modal.
  - Per-Function On-Demand Decompilation (`/api/function?path=...&addr=0x...`): Clicking any
    function in the sidebar disassembles, graphs, and decompiles that exact function in <15ms.
"""

from __future__ import annotations

import html
import http.server
import json
import os
import socketserver
import struct
import subprocess
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
from reverse_forge.whole_binary_function_indexer import WholeBinaryFunctionIndexer
from reverse_forge.project_workspace_db import ProjectWorkspaceDB
from reverse_forge.pipeline import PipelineStateMachine, AutonomyLevel


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>9R0JE6T R10T // R3V3R53-F0RG3 Studio v27.0</title>
<style>
:root {
  --bg-dark: #090d16;
  --bg-panel: #0f172a;
  --bg-card: #1e293b;
  --bg-hover: #334155;
  --border: #1e293b;
  --border-strong: #334155;
  --primary: #38bdf8;
  --primary-glow: rgba(56, 189, 248, 0.2);
  --accent: #a855f7;
  --success: #22c55e;
  --danger: #ef4444;
  --warning: #f59e0b;
  --text-main: #f1f5f9;
  --text-muted: #94a3b8;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
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
  font-size: 13px;
}

/* Header & Action Bar */
header {
  height: 48px;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border-strong);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  flex-shrink: 0;
  gap: 8px;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand-logo {
  font-family: var(--font-mono);
  font-weight: 800;
  font-size: 13px;
  letter-spacing: 0.4px;
  background: linear-gradient(135deg, var(--primary), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.badge {
  background: rgba(56, 189, 248, 0.14);
  color: var(--primary);
  border: 1px solid rgba(56, 189, 248, 0.35);
  padding: 2px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
}
.badge-accent {
  background: rgba(168, 85, 247, 0.15);
  color: #c084fc;
  border: 1px solid rgba(168, 85, 247, 0.35);
}

.nav-tabs { display: flex; gap: 4px; align-items: center; }
.nav-tab {
  background: transparent;
  color: var(--text-muted);
  border: 1px solid transparent;
  padding: 5px 10px;
  border-radius: 5px;
  cursor: pointer;
  font-size: 12px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.12s;
}
.nav-tab:hover { background: var(--bg-card); color: var(--text-main); }
.nav-tab.active {
  background: rgba(56, 189, 248, 0.14);
  color: var(--primary);
  border-color: rgba(56, 189, 248, 0.4);
}
kbd {
  background: #090d16;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  padding: 1px 4px;
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--text-muted);
}

.header-actions { display: flex; align-items: center; gap: 6px; }
.query-bar {
  background: var(--bg-dark);
  border: 1px solid var(--border-strong);
  color: var(--text-main);
  padding: 5px 10px;
  border-radius: 5px;
  width: 220px;
  font-size: 12px;
  font-family: var(--font-mono);
}
.query-bar:focus { outline: none; border-color: var(--primary); }

.btn {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border-strong);
  padding: 5px 9px;
  border-radius: 5px;
  cursor: pointer;
  font-size: 11px;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  transition: all 0.12s;
  white-space: nowrap;
}
.btn:hover { background: var(--bg-hover); border-color: var(--primary); }
.btn-primary {
  background: linear-gradient(135deg, #0284c7, #2563eb);
  border-color: #38bdf8;
  color: #fff;
}
.btn-primary:hover { filter: brightness(1.12); }
.btn-rust {
  background: rgba(245, 158, 11, 0.15);
  border-color: rgba(245, 158, 11, 0.45);
  color: #fbbf24;
}

/* Sub-Toolbar */
.sub-toolbar {
  height: 36px;
  background: #0b1120;
  border-bottom: 1px solid var(--border-strong);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  gap: 8px;
  flex-shrink: 0;
  overflow-x: auto;
}
.toolbar-group { display: flex; align-items: center; gap: 5px; }

/* 4-Pane Synchronized Split Workspace */
.workspace-root {
  flex: 1;
  display: flex;
  overflow: hidden;
}

/* Pane 1: Left Function & Symbol Dock */
.sidebar {
  width: 280px;
  background: var(--bg-panel);
  border-right: 1px solid var(--border-strong);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
}
.sidebar-tabs {
  display: flex;
  border-bottom: 1px solid var(--border-strong);
  background: #0b1120;
}
.sidebar-tab {
  flex: 1;
  padding: 7px 4px;
  text-align: center;
  font-size: 11px;
  font-weight: 600;
  color: var(--text-muted);
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
}
.sidebar-tab.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
  background: rgba(56, 189, 248, 0.06);
}
.sidebar-search {
  padding: 6px 8px;
  border-bottom: 1px solid var(--border-strong);
}
.sidebar-search input {
  width: 100%;
  background: var(--bg-dark);
  border: 1px solid var(--border-strong);
  color: var(--text-main);
  padding: 5px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
}
.sidebar-list {
  flex: 1;
  overflow-y: auto;
}
.list-item {
  padding: 6px 10px;
  border-bottom: 1px solid rgba(255,255,255,0.03);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  cursor: pointer;
  font-family: var(--font-mono);
  font-size: 11.5px;
}
.list-item:hover { background: var(--bg-card); }
.list-item.active {
  background: rgba(56, 189, 248, 0.16);
  border-left: 3px solid var(--primary);
}
.item-name {
  color: var(--text-main);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.item-meta { display: flex; align-items: center; gap: 5px; flex-shrink: 0; }
.item-addr { color: var(--primary); font-size: 10.5px; }
.kind-pill {
  font-size: 9px;
  padding: 1px 4px;
  border-radius: 3px;
  font-weight: 700;
  text-transform: uppercase;
}
.kind-main { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34,197,94,0.4); }
.kind-entry { background: rgba(56, 189, 248, 0.2); color: #38bdf8; }
.kind-plt_import { background: rgba(168, 85, 247, 0.2); color: #c084fc; }
.kind-sub { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; }

/* Center + Bottom Dock Container */
.center-dock-column {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* Top Split Row: Center-Left (CFG / Linear Disasm) + Center-Right (Decompiled C / Multi-IR) */
.top-split-row {
  flex: 1.55;
  display: flex;
  overflow: hidden;
  border-bottom: 1px solid var(--border-strong);
  min-height: 240px;
}

.pane-box {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  border-right: 1px solid var(--border-strong);
  position: relative;
}
.pane-box:last-child { border-right: none; }

.pane-header {
  height: 32px;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border-strong);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 10px;
  flex-shrink: 0;
}
.pane-title {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 8px;
}
.pane-subtabs { display: flex; gap: 3px; }
.pane-subtab {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  padding: 2px 8px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-size: 11px;
  cursor: pointer;
}
.pane-subtab.active {
  background: rgba(56, 189, 248, 0.15);
  color: var(--primary);
  border-color: rgba(56, 189, 248, 0.35);
}

/* CFG Interactive Pan/Zoom Canvas */
#cfg-canvas {
  flex: 1;
  position: relative;
  overflow: hidden;
  background-color: var(--bg-dark);
  background-image: radial-gradient(#1e293b 1px, transparent 1px);
  background-size: 20px 20px;
  cursor: grab;
}
#cfg-canvas:active { cursor: grabbing; }
#cfg-viewport {
  position: absolute;
  top: 0;
  left: 0;
  width: 4000px;
  height: 4000px;
  transform-origin: 0 0;
}
#cfg-links-layer {
  position: absolute;
  top: 0;
  left: 0;
  width: 4000px;
  height: 4000px;
  pointer-events: none;
}
#cfg-nodes-layer {
  position: absolute;
  top: 0;
  left: 0;
  width: 4000px;
  height: 4000px;
}
.cfg-node {
  position: absolute;
  background: rgba(15, 23, 42, 0.96);
  border: 1px solid #475569;
  border-radius: 6px;
  box-shadow: 0 8px 20px rgba(0,0,0,0.55);
  font-family: var(--font-mono);
  font-size: 11.5px;
  width: 330px;
  transition: border-color 0.12s;
}
.cfg-node:hover, .cfg-node.selected {
  border-color: var(--primary);
  box-shadow: 0 0 0 1px var(--primary), 0 8px 24px rgba(56,189,248,0.2);
}
.cfg-node-hdr {
  background: #1e293b;
  padding: 5px 9px;
  font-weight: 700;
  color: var(--primary);
  border-bottom: 1px solid #334155;
  display: flex;
  justify-content: space-between;
  border-radius: 5px 5px 0 0;
}
.cfg-node-body { padding: 6px 8px; line-height: 1.5; }
.cfg-insn {
  display: flex;
  gap: 8px;
  padding: 1px 4px;
  border-radius: 3px;
  cursor: pointer;
}
.cfg-insn:hover, .cfg-insn.sync-hi { background: rgba(56, 189, 248, 0.22); }
.cfg-va { color: #64748b; width: 58px; flex-shrink: 0; font-size: 10.5px; }
.cfg-mnem { color: #f43f5e; font-weight: 600; width: 52px; flex-shrink: 0; }
.cfg-ops { color: #e2e8f0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.graph-controls {
  position: absolute;
  bottom: 10px;
  right: 12px;
  display: flex;
  gap: 4px;
  background: rgba(15, 23, 42, 0.9);
  padding: 4px;
  border-radius: 6px;
  border: 1px solid var(--border-strong);
  z-index: 10;
}
.graph-btn {
  background: var(--bg-card);
  color: var(--text-main);
  border: 1px solid var(--border-strong);
  border-radius: 4px;
  padding: 3px 7px;
  font-family: var(--font-mono);
  font-size: 11px;
  cursor: pointer;
}
.graph-btn:hover { border-color: var(--primary); }

/* Linear Disassembly Table & Code View */
.code-view {
  flex: 1;
  overflow: auto;
  padding: 10px 12px;
  background: var(--bg-dark);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.58;
}
.code-line {
  display: flex;
  padding: 1px 6px;
  border-radius: 3px;
  cursor: pointer;
}
.code-line:hover, .code-line.sync-hi {
  background: rgba(56, 189, 248, 0.18);
}
.code-num {
  width: 38px;
  color: #475569;
  user-select: none;
  text-align: right;
  padding-right: 12px;
  flex-shrink: 0;
}
.code-text { flex: 1; color: #e2e8f0; white-space: pre; }
.kw { color: #f43f5e; font-weight: 600; }
.type { color: var(--primary); }
.func { color: #34d399; font-weight: 600; }
.num { color: #fbbf24; }
.str-lit { color: #a3e635; }
.cmt { color: #64748b; font-style: italic; }

/* Bottom Dock: Hex + 14-Format Inspector + Console + Mitigations */
.bottom-dock {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background: var(--bg-dark);
  min-height: 190px;
}
.bottom-body {
  flex: 1;
  display: flex;
  overflow: hidden;
}
.bottom-tab-panel {
  display: none;
  flex: 1;
  overflow: hidden;
}
.bottom-tab-panel.active {
  display: flex;
}

.hex-split { display: flex; flex: 1; overflow: hidden; }
.hex-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  font-family: var(--font-mono);
  font-size: 12px;
}
.hex-header {
  padding: 5px 14px;
  background: #0b1120;
  border-bottom: 1px solid var(--border-strong);
  display: flex;
  gap: 20px;
  color: var(--text-muted);
  font-size: 11px;
}
.hex-body { flex: 1; overflow-y: auto; padding: 8px 14px; line-height: 1.55; }
.hex-row { display: flex; gap: 18px; padding: 1px 4px; border-radius: 3px; }
.hex-row.sync-hi { background: rgba(56, 189, 248, 0.2); }
.hex-offset { color: var(--accent); user-select: none; width: 84px; flex-shrink: 0; }
.hex-bytes { display: flex; gap: 6px; color: #cbd5e1; }
.hex-byte { padding: 0 2px; border-radius: 2px; cursor: pointer; }
.hex-byte:hover { background: var(--primary); color: #090d16; }
.hex-ascii { color: #94a3b8; letter-spacing: 1px; white-space: pre; }

.inspector-drawer {
  width: 340px;
  background: var(--bg-panel);
  border-left: 1px solid var(--border-strong);
  padding: 10px 12px;
  overflow-y: auto;
  font-family: var(--font-mono);
  font-size: 11.5px;
}
.insp-row {
  display: flex;
  justify-content: space-between;
  padding: 4px 0;
  border-bottom: 1px solid rgba(255,255,255,0.04);
}
.insp-key { color: var(--text-muted); }
.insp-val {
  color: var(--primary);
  font-weight: 600;
  text-align: right;
  max-width: 195px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.hud-grid {
  flex: 1;
  overflow-y: auto;
  padding: 12px 16px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 10px;
}
.hud-card {
  background: var(--bg-panel);
  border: 1px solid var(--border-strong);
  border-radius: 6px;
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  position: relative;
}
.hud-card::before { content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%; background: var(--primary); }
.hud-card.pass::before { background: var(--success); }
.hud-card.fail::before { background: var(--danger); }
.hud-title { font-size: 10.5px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; }
.hud-val { font-size: 13.5px; font-weight: 800; font-family: var(--font-mono); }
.hud-desc { font-size: 11px; color: var(--text-muted); line-height: 1.35; }

/* In-App Non-Blocking Command Modal (Zero window.prompt!) */
.modal-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(9, 13, 22, 0.78);
  z-index: 200;
  align-items: center;
  justify-content: center;
}
.modal-backdrop.open { display: flex; }
.modal-card {
  background: var(--bg-panel);
  border: 1px solid var(--primary);
  border-radius: 8px;
  width: 440px;
  padding: 16px;
  box-shadow: 0 20px 50px rgba(0,0,0,0.75);
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.modal-title { font-family: var(--font-mono); font-weight: 700; color: var(--primary); font-size: 13px; }
.modal-field { display: flex; flex-direction: column; gap: 4px; }
.modal-field label { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); }
.modal-field input, .modal-field select {
  background: var(--bg-dark);
  border: 1px solid var(--border-strong);
  color: var(--text-main);
  padding: 7px 10px;
  border-radius: 5px;
  font-family: var(--font-mono);
  font-size: 12px;
}
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px; }

footer {
  height: 26px;
  background: #0b1120;
  border-top: 1px solid var(--border-strong);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  flex-shrink: 0;
}
.status-left, .status-right { display: flex; gap: 16px; }
.status-item strong { color: var(--text-main); }
</style>
</head>
<body ondragover="event.preventDefault()" ondrop="handleDropFile(event)">

<header>
  <div class="brand">
    <div class="brand-logo">9R0JE6T R10T // R3V3R53-F0RG3</div>
    <span class="badge" id="binary-format-badge">ELF / PE / Mach-O</span>
    <span class="badge badge-accent" id="active-func-badge">main @ 0x4730</span>
    <span style="font-size:11.5px;color:var(--text-muted);font-family:var(--font-mono);" id="binary-name-label">Ready</span>
  </div>

  <nav class="nav-tabs">
    <button class="nav-tab active" onclick="switchView('cfg')"><span>⬡ Graph CFG</span> <kbd>Space</kbd></button>
    <button class="nav-tab" onclick="switchView('disasm')"><span>≡ Disassembly</span></button>
    <button class="nav-tab" onclick="switchView('decomp')"><span>⚙ Decompiled C</span> <kbd>F5</kbd></button>
    <button class="nav-tab" onclick="switchBottomTab('hex')"><span># Hex Inspector</span></button>
    <button class="nav-tab" onclick="switchBottomTab('hud')"><span>🛡 Mitigations HUD</span></button>
    <button class="nav-tab" onclick="switchBottomTab('console')"><span>🦀 Rust & Triage Console</span></button>
  </nav>

  <div class="header-actions">
    <input type="text" id="smart-query-input" class="query-bar" placeholder="Search or Ask (main, 0x4730, network, yara)..." onkeydown="if(event.key==='Enter')runSmartQuery()">
    <button class="btn" onclick="runSmartQuery()">Ask</button>
    <input type="file" id="file-upload-input" style="display:none" onchange="uploadBinaryFile(this.files[0])">
    <button class="btn btn-primary" onclick="document.getElementById('file-upload-input').click()"><span>📂 Upload Binary</span></button>
    <button class="btn" onclick="loadBinaryFromServer('/bin/ls')" title="One-click load /bin/ls (158 functions)"><span>⚡ Load /bin/ls</span></button>
    <button class="btn" onclick="openPathModal()"><span>Open Path</span></button>
  </div>
</header>

<div class="sub-toolbar">
  <div class="toolbar-group">
    <span style="color:var(--text-muted);font-family:var(--font-mono);font-size:11px;">DEBUGGER:</span>
    <button class="btn" onclick="debuggerStep()"><span>⏮ Step</span> <kbd>F7</kbd></button>
    <button class="btn" onclick="debuggerContinue()"><span>▶ Continue</span> <kbd>F9</kbd></button>
    <button class="btn" onclick="debuggerToggleBP()"><span>🔴 BP</span> <kbd>F2</kbd></button>
    <span id="dbg-rip-badge" style="font-family:var(--font-mono);color:var(--success);font-size:11px;margin:0 6px;">RIP: 0x00401000</span>
  </div>
  <div class="toolbar-group">
    <button class="btn" onclick="openRenameModal()"><span>✏ Rename</span> <kbd>N</kbd></button>
    <button class="btn" onclick="openCommentModal()"><span>💬 Comment</span> <kbd>;</kbd></button>
    <button class="btn" onclick="openJumpModal()"><span>🎯 Jump</span> <kbd>G</kbd></button>
    <button class="btn" onclick="openPatchModal()"><span>🩹 Patch Bytes</span></button>
    <button class="btn" onclick="runCPUEmulation()"><span>🚀 Emulate CPU</span></button>
    <button class="btn" onclick="runForceExecVisor()"><span>🔥 Force-Exec Visor</span></button>
    <button class="btn" onclick="runVulnAudit()"><span>🛡 CWE Audit</span></button>
    <button class="btn" onclick="runYaraGenerator()"><span>🧬 YARA/SIGMA</span></button>
    <button class="btn btn-rust" onclick="runNativeRustOmniAudit()"><span>🦀 Rust Omni-Audit (55 Modules)</span></button>
    <button class="btn" onclick="exportCHeader()"><span>⬇ .h Header</span></button>
    <button class="btn" onclick="runFullPipeline()"><span>⚡ 12-Stage Report</span></button>
  </div>
</div>

<!-- 4-Pane Synchronized Split Workspace -->
<div class="workspace-root">
  <!-- Pane 1: Left Function & Symbol Dock -->
  <aside class="sidebar">
    <div class="sidebar-tabs">
      <button class="sidebar-tab active" id="tab-btn-funcs" onclick="switchSidebarTab('funcs')">Funcs (<span id="funcs-count">0</span>)</button>
      <button class="sidebar-tab" id="tab-btn-strings" onclick="switchSidebarTab('strings')">Strings (<span id="strings-count">0</span>)</button>
      <button class="sidebar-tab" id="tab-btn-sections" onclick="switchSidebarTab('sections')">Sections</button>
      <button class="sidebar-tab" id="tab-btn-xrefs" onclick="switchSidebarTab('xrefs')">Xrefs</button>
    </div>
    <div class="sidebar-search">
      <input type="text" id="filter-input" placeholder="Filter functions / symbols / strings (/) ..." oninput="filterSidebar()">
    </div>
    <div class="sidebar-list" id="sidebar-list"></div>
  </aside>

  <!-- Right 3 Panes: Top Split (CFG/Disasm + Decompiled C/Multi-IR) & Bottom Dock (Hex/Inspector/Console/HUD) -->
  <div class="center-dock-column">
    <div class="top-split-row">
      <!-- Pane 2: Center-Left CFG Graph & Linear Disassembly -->
      <div class="pane-box" id="left-center-pane">
        <div class="pane-header">
          <div class="pane-title">
            <span>DISASSEMBLY & CONTROL-FLOW GRAPH</span>
            <span id="cfg-stats-badge" style="color:var(--primary)"></span>
          </div>
          <div class="pane-subtabs">
            <button class="pane-subtab active" id="subtab-cfg" onclick="switchLeftPaneMode('cfg')">⬡ Graph CFG</button>
            <button class="pane-subtab" id="subtab-disasm" onclick="switchLeftPaneMode('disasm')">≡ Linear ASM</button>
          </div>
        </div>

        <!-- Interactive Pan/Zoom CFG Canvas -->
        <div id="cfg-canvas" onmousedown="startCfgPan(event)" onmousemove="moveCfgPan(event)" onmouseup="endCfgPan()" onmouseleave="endCfgPan()" onwheel="wheelCfgZoom(event)">
          <div id="cfg-viewport">
            <svg id="cfg-links-layer" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <marker id="arrow-true" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#22c55e" />
                </marker>
                <marker id="arrow-false" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
                </marker>
              </defs>
            </svg>
            <div id="cfg-nodes-layer"></div>
          </div>
          <div class="graph-controls">
            <button class="graph-btn" onclick="zoomGraph(1.2)" title="Zoom In">+</button>
            <button class="graph-btn" onclick="zoomGraph(0.82)" title="Zoom Out">−</button>
            <button class="graph-btn" onclick="resetGraphZoom()" title="Reset Pan/Zoom">Center</button>
          </div>
        </div>

        <!-- Linear Disassembly View -->
        <div id="disasm-view" class="code-view" style="display:none;"></div>
      </div>

      <!-- Pane 3: Center-Right Synchronized Decompiler & Multi-IR -->
      <div class="pane-box" id="right-center-pane">
        <div class="pane-header">
          <div class="pane-title">
            <span>SYNCHRONIZED DECOMPILER & MULTI-IR</span>
          </div>
          <div class="pane-subtabs">
            <button class="pane-subtab active" id="irtab-c" onclick="switchIrTab('c')">Decompiled C</button>
            <button class="pane-subtab" id="irtab-pcode" onclick="switchIrTab('pcode')">Ghidra P-Code</button>
            <button class="pane-subtab" id="irtab-esil" onclick="switchIrTab('esil')">Rizin ESIL</button>
            <button class="pane-subtab" id="irtab-vex" onclick="switchIrTab('vex')">angr VEX</button>
          </div>
        </div>
        <div id="code-content" class="code-view"></div>
      </div>
    </div>

    <!-- Pane 4: Bottom Synchronized Hex, 14-Format Inspector, Console & Mitigations HUD -->
    <div class="bottom-dock">
      <div class="pane-header">
        <div class="pane-title">
          <span>SYNCHRONIZED HEX INSPECTOR, SECURITY HUD & NATIVE ENGINE CONSOLE</span>
        </div>
        <div class="pane-subtabs">
          <button class="pane-subtab active" id="btab-hex" onclick="switchBottomTab('hex')"># Hex & 14-Format Inspector</button>
          <button class="pane-subtab" id="btab-console" onclick="switchBottomTab('console')">🦀 Engine Output & Triage Console</button>
          <button class="pane-subtab" id="btab-hud" onclick="switchBottomTab('hud')">🛡 Mitigations HUD</button>
          <button class="pane-subtab" id="btab-intel" onclick="switchBottomTab('intel')">🧠 Capabilities & Strings</button>
        </div>
      </div>

      <div class="bottom-body">
        <!-- Bottom Tab 1: Synchronized Hex + 14-Format Data Inspector -->
        <div class="bottom-tab-panel active" id="bpanel-hex">
          <div class="hex-split">
            <div class="hex-container">
              <div class="hex-header">
                <span style="width:84px">VA / OFFSET</span>
                <span style="flex:1">00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</span>
                <span style="width:140px">ASCII</span>
              </div>
              <div class="hex-body" id="hex-rows"></div>
            </div>
            <div class="inspector-drawer">
              <div style="font-weight:700;color:var(--primary);margin-bottom:6px;border-bottom:1px solid var(--border-strong);padding-bottom:4px;">
                IMHEX 14-FORMAT DATA INSPECTOR
              </div>
              <div id="inspector-rows">
                <div class="insp-row"><span class="insp-key">Click any byte or instruction</span><span class="insp-val">Ready</span></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Bottom Tab 2: Interactive Engine Output & Native Rust Console -->
        <div class="bottom-tab-panel" id="bpanel-console">
          <div style="display:flex;flex:1;overflow:hidden;">
            <div style="width:230px;background:var(--bg-panel);border-right:1px solid var(--border-strong);padding:8px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;">
              <div style="font-size:10.5px;font-weight:700;color:var(--text-muted);margin-bottom:4px;font-family:var(--font-mono);">ONE-CLICK NATIVE RUST ENGINES</div>
              <button class="btn" onclick="execNativeRustCmd('omni-audit')">🦀 200-Phase Master Audit</button>
              <button class="btn" onclick="execNativeRustCmd('die-scan')">📦 Detect-It-Easy (DIE) Scan</button>
              <button class="btn" onclick="execNativeRustCmd('sleigh-lift')">⚙ Ghidra SLEIGH ARM64/RV64C</button>
              <button class="btn" onclick="execNativeRustCmd('esil')">🧮 Rizin ESIL RPN Evaluator</button>
              <button class="btn" onclick="execNativeRustCmd('vex-lift')">🔬 angr VEX + Claripy Solver</button>
              <button class="btn" onclick="execNativeRustCmd('yara-ac')">🧬 YARA Aho-Corasick $O(N)$</button>
              <button class="btn" onclick="execNativeRustCmd('softmmu')">🦄 Unicorn SoftMMU + CoW TLB</button>
              <button class="btn" onclick="execNativeRustCmd('typefactory')">🏗 Ghidra TypeFactory Structs</button>
              <button class="btn" onclick="execNativeRustCmd('wl-bindiff')">🔀 Diaphora WL Graph Diff</button>
              <button class="btn" onclick="execNativeRustCmd('galileo-cfi')">🛡 Galileo CFI / CET Audit</button>
              <button class="btn" onclick="execNativeRustCmd('frida-stalker')">🪝 Frida Stalker Relocator</button>
              <button class="btn" onclick="execNativeRustCmd('volatility3')">🧠 Volatility3 IA-32e Walker</button>
              <button class="btn" onclick="execNativeRustCmd('pesieve')">🔍 PE-sieve Inline Hook Scan</button>
              <button class="btn" onclick="execNativeRustCmd('triton-dse')">🎯 Triton / SymCC Branch Flip</button>
              <button class="btn" onclick="execNativeRustCmd('rr-timetravel')">⏪ Mozilla rr Time-Travel</button>
              <button class="btn" onclick="execNativeRustCmd('qbdi-drcov')">📊 QBDI Shadow-Stack & drcov</button>
            </div>
            <pre id="console-output" class="code-view" style="margin:0;white-space:pre-wrap;color:#e2e8f0;">[R3V3R53//F0RG3 Studio v27.0 Ready]
• Click "⚡ Load /bin/ls" or "📂 Upload Binary" in the top bar to index all functions, PLT/GOT symbols, and strings.
• Click any function in the left sidebar to disassemble, build its Sugiyama CFG, and decompile it to C / P-Code / ESIL / VEX in &lt;15ms.</pre>
          </div>
        </div>

        <!-- Bottom Tab 3: Mitigations HUD -->
        <div class="bottom-tab-panel" id="bpanel-hud">
          <div class="hud-grid" id="hud-grid"></div>
        </div>

        <!-- Bottom Tab 4: Capabilities & Smart Query Results -->
        <div class="bottom-tab-panel" id="bpanel-intel">
          <div class="hud-grid" id="intel-grid"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- In-App Non-Blocking Action Modal -->
<div class="modal-backdrop" id="action-modal">
  <div class="modal-card">
    <div class="modal-title" id="modal-title">Action</div>
    <div id="modal-fields"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeActionModal()">Cancel <kbd>Esc</kbd></button>
      <button class="btn btn-primary" id="modal-submit-btn">Apply <kbd>Enter</kbd></button>
    </div>
  </div>
</div>

<footer>
  <div class="status-left">
    <div class="status-item">Engine: <strong>R3V3R53//F0RG3 v27.0 (55 Native Rust Modules + Whole-Binary Indexer)</strong></div>
    <div class="status-item">Current VA: <strong id="status-va">0x00401000</strong></div>
  </div>
  <div class="status-right">
    <div class="status-item">Hover Byte: <strong id="status-byte">0x00 (0)</strong></div>
    <div class="status-item">Status: <strong style="color:var(--success)" id="sync-status">READY</strong></div>
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
  currentBinaryPath: "",
  format: "ELF",
  architecture: "x86-64 (AMD64)",
  entryPoint: "0x4730",
  activeFunctionName: "main",
  activeFunctionVa: "0x4730",
  functions: [
    { name: "main", addr: "0x4730", size: 420, kind: "main", call_count: 1 },
    { name: "_start", addr: "0x61d0", size: 48, kind: "entry", call_count: 1 }
  ],
  strings: [
    { value: "coreutils", type: "rodata", addr: "0x1bbfc" },
    { value: "/usr/share/locale", type: "rodata", addr: "0x1bc2e" }
  ],
  sections: [
    { name: ".text", vaddr: "0x46b0", vsize: 86174, perms: "R-X" },
    { name: ".rodata", vaddr: "0x1a000", vsize: 20346, perms: "R--" }
  ],
  mitigations: {
    "ASLR / PIE": { pass: true, val: "Enabled (Position-Independent Executable)" },
    "DEP / NX": { pass: true, val: "Enforced (PT_GNU_STACK R-W)" },
    "Stack Canary": { pass: true, val: "Active (__stack_chk_fail / fs:[0x28])" }
  },
  capabilities: [],
  xrefs: [],
  disassemblyLines: [
    { va: "0x4730", bytes: "4157", mnem: "push", ops: "r15", comment: "" },
    { va: "0x4746", bytes: "4c8d25af740100", mnem: "lea", ops: "r12, [rip + 0x174af]", comment: "\"coreutils\" (@ 0x1bbfc)" },
    { va: "0x4781", bytes: "e84afdffff", mnem: "call", ops: "setlocale@plt (0x44d0)", comment: "" },
    { va: "0x4790", bytes: "e84bfaffff", mnem: "call", ops: "bindtextdomain@plt (0x41e0)", comment: "" },
    { va: "0x479f", bytes: "e8fcf9ffff", mnem: "call", ops: "textdomain@plt (0x41a0)", comment: "" }
  ],
  cfgBlocks: [
    {
      id: 0, x: 180, y: 36, addr: "0x4730", label: "main: 0x4730",
      insns: [
        { va: "0x4730", mnem: "push", ops: "r15" },
        { va: "0x4746", mnem: "lea", ops: "r12, [rip + 0x174af] ; \"coreutils\"" },
        { va: "0x4781", mnem: "call", ops: "setlocale@plt (0x44d0)" },
        { va: "0x4790", mnem: "call", ops: "bindtextdomain@plt (0x41e0)" },
        { va: "0x479f", mnem: "call", ops: "textdomain@plt (0x41a0)" }
      ],
      successors: []
    }
  ],
  hexRows: [],
  pseudocode: [
    "// Function: main @ 0x4730",
    "int main(int argc, char** argv) {",
    "    uint64_t stack_canary = __readfsqword(0x28);             // @ 0x475b",
    "    rax = setlocale(0x6, \"\");                                // @ 0x4781",
    "    rax = bindtextdomain(\"coreutils\", \"/usr/share/locale\");  // @ 0x4790",
    "    rax = textdomain(\"coreutils\");                           // @ 0x479f",
    "    return rax;",
    "}"
  ],
  pcodeText: "0x4781: rax = CALL setlocale(0x6, \"\")\n0x4790: rax = CALL bindtextdomain(\"coreutils\", \"/usr/share/locale\")\n0x479f: rax = CALL textdomain(\"coreutils\")",
  esilText: "0x4781: setlocale,CALL\n0x4790: bindtextdomain,CALL\n0x479f: textdomain,CALL",
  vexText: "IRSB { addr=0x4730, arch=\"x64\" }\n   CALL setlocale(0x6, \"\")\n   CALL bindtextdomain(\"coreutils\", \"/usr/share/locale\")"
};

let activeSidebarTab = 'funcs';
let activeIrTab = 'c';
let currentZoom = 1.0;
let panX = 0, panY = 0;
let isPanning = false, panStartX = 0, panStartY = 0;

function setStatus(msg, color) {
  const el = document.getElementById('sync-status');
  el.innerText = msg;
  el.style.color = color || 'var(--success)';
}

function logConsole(title, bodyText) {
  switchBottomTab('console');
  const out = document.getElementById('console-output');
  const ts = new Date().toLocaleTimeString();
  out.textContent = `[${ts}] === ${title} ===\n${bodyText}\n\n` + out.textContent;
}

function switchLeftPaneMode(mode) {
  document.getElementById('subtab-cfg').classList.toggle('active', mode === 'cfg');
  document.getElementById('subtab-disasm').classList.toggle('active', mode === 'disasm');
  document.getElementById('cfg-canvas').style.display = (mode === 'cfg') ? 'block' : 'none';
  document.getElementById('disasm-view').style.display = (mode === 'disasm') ? 'block' : 'none';
}

function switchView(viewId) {
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  const tabBtn = Array.from(document.querySelectorAll('.nav-tab')).find(b => (b.getAttribute('onclick') || '').includes(viewId));
  if (tabBtn) tabBtn.classList.add('active');

  if (viewId === 'cfg') {
    switchLeftPaneMode('cfg');
  } else if (viewId === 'disasm') {
    switchLeftPaneMode('disasm');
  } else if (viewId === 'decomp') {
    switchIrTab('c');
  } else if (viewId === 'hex' || viewId === 'hud' || viewId === 'intel' || viewId === 'console') {
    switchBottomTab(viewId);
  }
}

function switchIrTab(tab) {
  activeIrTab = tab;
  ['c', 'pcode', 'esil', 'vex'].forEach(k => {
    const btn = document.getElementById('irtab-' + k);
    if (btn) btn.classList.toggle('active', k === tab);
  });
  renderDecomp();
}

function switchBottomTab(tab) {
  ['hex', 'console', 'hud', 'intel'].forEach(k => {
    const b = document.getElementById('btab-' + k);
    const p = document.getElementById('bpanel-' + k);
    if (b) b.classList.toggle('active', k === tab);
    if (p) p.classList.toggle('active', k === tab);
  });
}

function switchSidebarTab(tab) {
  activeSidebarTab = tab;
  document.querySelectorAll('.sidebar-tab').forEach(t => t.classList.remove('active'));
  const btn = document.getElementById('tab-btn-' + tab);
  if (btn) btn.classList.add('active');
  renderSidebar();
}

function renderSidebar() {
  const container = document.getElementById('sidebar-list');
  container.innerHTML = '';
  const filter = (document.getElementById('filter-input').value || '').toLowerCase();

  if (activeSidebarTab === 'funcs') {
    appData.functions
      .filter(f => f.name.toLowerCase().includes(filter) || String(f.addr).toLowerCase().includes(filter))
      .forEach(f => {
        const el = document.createElement('div');
        const isActive = (String(f.addr).toLowerCase() === String(appData.activeFunctionVa).toLowerCase());
        el.className = 'list-item' + (isActive ? ' active' : '');
        const kind = f.kind || 'sub';
        const pill = `<span class="kind-pill kind-${escHtml(kind)}">${escHtml(kind === 'plt_import' ? 'PLT' : kind)}</span>`;
        el.innerHTML = `
          <span class="item-name" title="${escHtml(f.name)}">${escHtml(f.name)}</span>
          <span class="item-meta">${pill}<span class="item-addr">${escHtml(f.addr)}</span></span>
        `;
        el.onclick = () => selectAndDecompileFunction(f.addr, f.name);
        container.appendChild(el);
      });
  } else if (activeSidebarTab === 'strings') {
    appData.strings
      .filter(s => s.value.toLowerCase().includes(filter) || String(s.addr).toLowerCase().includes(filter))
      .forEach(s => {
        const el = document.createElement('div');
        el.className = 'list-item';
        el.innerHTML = `<span class="item-name" title="${escHtml(s.value)}">"${escHtml(s.value)}"</span><span class="item-addr">${escHtml(s.addr)}</span>`;
        el.onclick = () => syncHighlightAddress(s.addr);
        container.appendChild(el);
      });
  } else if (activeSidebarTab === 'sections') {
    appData.sections.forEach(s => {
      const el = document.createElement('div');
      el.className = 'list-item';
      const va = s.vaddr || s.virtual_address || '0x0';
      el.innerHTML = `<span class="item-name"><strong>${escHtml(s.name)}</strong> (${escHtml(s.perms || 'R-X')})</span><span class="item-addr">${escHtml(va)}</span>`;
      el.onclick = () => loadHexAtOffset(va);
      container.appendChild(el);
    });
  } else if (activeSidebarTab === 'xrefs') {
    (appData.xrefs || []).forEach(x => {
      const el = document.createElement('div');
      el.className = 'list-item';
      el.innerHTML = `<span class="item-name">${escHtml(x.from_va)} → ${escHtml(x.resolved_target_preview || x.to_va)}</span><span class="item-addr">${escHtml(x.xref_type)}</span>`;
      el.onclick = () => selectAndDecompileFunction(x.to_va, x.resolved_target_preview);
      container.appendChild(el);
    });
  }
}

function selectAndDecompileFunction(va, nameHint) {
  document.getElementById('status-va').innerText = va;
  const path = appData.binaryPath || appData.currentBinaryPath;
  if (!path) {
    syncHighlightAddress(va);
    return;
  }
  setStatus(`DECOMPILING ${nameHint || va}...`, 'var(--warning)');
  fetch(`/api/function?path=${encodeURIComponent(path)}&addr=${encodeURIComponent(va)}`)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok' && data.function) {
        const fn = data.function;
        appData.activeFunctionName = fn.name;
        appData.activeFunctionVa = fn.addr;
        document.getElementById('active-func-badge').innerText = `${fn.name} @ ${fn.addr}`;
        appData.disassemblyLines = fn.disassembly_lines || [];
        appData.cfgBlocks = fn.cfg_blocks || [];
        appData.pseudocode = (fn.decompiled_c || '').split('\n');
        appData.pcodeText = fn.pcode_ssa_text || '';
        appData.esilText = fn.rizin_esil_text || '';
        appData.vexText = fn.angr_vex_text || '';
        if (fn.hex_rows && fn.hex_rows.length > 0) {
          appData.hexRows = fn.hex_rows;
        }
        resetGraphZoom();
        renderSidebar();
        renderCFGGraph();
        renderLinearDisassembly();
        renderDecomp();
        renderHexView();
        inspectByteOffset(fn.addr);
        setStatus(`SYNCHRONIZED: ${fn.name} (${appData.disassemblyLines.length} insns, ${appData.cfgBlocks.length} blocks)`, 'var(--success)');
      } else {
        setStatus('FUNCTION DECOMPILE ERROR', 'var(--danger)');
      }
    });
}

function syncHighlightAddress(va) {
  if (!va) return;
  const norm = String(va).toLowerCase();
  document.getElementById('status-va').innerText = va;

  document.querySelectorAll('[data-va]').forEach(el => {
    const match = (el.getAttribute('data-va') || '').toLowerCase() === norm;
    el.classList.toggle('sync-hi', match);
    if (match && el.scrollIntoView) {
      el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  });

  inspectByteOffset(va);
}

function renderLinearDisassembly() {
  const container = document.getElementById('disasm-view');
  container.innerHTML = '';
  (appData.disassemblyLines || []).forEach(ins => {
    const row = document.createElement('div');
    row.className = 'code-line';
    row.setAttribute('data-va', ins.va);
    const cmt = ins.comment ? `  <span class="cmt">; ${escHtml(ins.comment)}</span>` : '';
    row.innerHTML = `
      <div class="code-num" style="width:76px;color:var(--primary)">${escHtml(ins.va)}</div>
      <div class="code-num" style="width:115px;color:#64748b;text-align:left">${escHtml((ins.bytes || '').slice(0, 14))}</div>
      <div class="code-text"><span class="kw">${escHtml(ins.mnem.padEnd(8))}</span> ${escHtml(ins.ops)}${cmt}</div>
    `;
    row.onclick = () => syncHighlightAddress(ins.va);
    container.appendChild(row);
  });
}

function renderDecomp() {
  const container = document.getElementById('code-content');
  container.innerHTML = '';
  let lines = appData.pseudocode || [];
  if (activeIrTab === 'pcode') lines = (appData.pcodeText || '').split('\n');
  if (activeIrTab === 'esil') lines = (appData.esilText || '').split('\n');
  if (activeIrTab === 'vex') lines = (appData.vexText || '').split('\n');

  lines.forEach((line, idx) => {
    let safeLine = escHtml(line);
    // Extract `@ 0x...` or leading `0x...:` for bidirectional click sync
    let lineVa = '';
    const mAt = line.match(/@\s*(0x[0-9a-fA-F]+)/);
    const mLead = line.match(/^\s*(0x[0-9a-fA-F]+):/);
    if (mAt) lineVa = mAt[1];
    else if (mLead) lineVa = mLead[1];

    let colored = safeLine
      .replace(/(&quot;.*?&quot;)/g, '<span class="str-lit">$1</span>')
      .replace(/(\/\/.*$)/g, '<span class="cmt">$1</span>')
      .replace(/\b(int64_t|uint64_t|int32_t|uint32_t|uint16_t|uint8_t|int|long|char|void|typedef|struct)\b/g, '<span class="type">$1</span>')
      .replace(/\b(if|else|while|do|switch|case|default|break|goto|return|CALL|COPY|INT_ADD|INT_SUB|CBRANCH|RETURN)\b/g, '<span class="kw">$1</span>')
      .replace(/(\b0x[0-9a-fA-F]+\b|\b\d+\b)/g, '<span class="num">$1</span>');

    const row = document.createElement('div');
    row.className = 'code-line';
    if (lineVa) row.setAttribute('data-va', lineVa);
    row.innerHTML = `<div class="code-num">${idx + 1}</div><div class="code-text">${colored}</div>`;
    if (lineVa) row.onclick = () => syncHighlightAddress(lineVa);
    container.appendChild(row);
  });
}

function renderHexView() {
  const container = document.getElementById('hex-rows');
  container.innerHTML = '';
  const rows = (appData.hexRows && appData.hexRows.length > 0) ? appData.hexRows : [];
  rows.forEach(hr => {
    const row = document.createElement('div');
    row.className = 'hex-row';
    row.setAttribute('data-va', hr.offset);
    const bytesSpans = (hr.bytes || []).map(bHex => {
      const decVal = parseInt(bHex, 16) || 0;
      return `<span class="hex-byte" onmouseover="updateHoverByte('0x${escHtml(bHex)}', ${decVal})" onclick="inspectByteOffset('${escHtml(hr.offset)}')">${escHtml(bHex)}</span>`;
    }).join('');
    row.innerHTML = `<div class="hex-offset">${escHtml(hr.offset)}</div><div class="hex-bytes">${bytesSpans}</div><div class="hex-ascii">${escHtml(hr.ascii)}</div>`;
    container.appendChild(row);
  });
}

function loadHexAtOffset(offsetHex) {
  const path = appData.binaryPath || appData.currentBinaryPath;
  if (!path) return;
  fetch(`/api/hex?path=${encodeURIComponent(path)}&offset=${encodeURIComponent(offsetHex)}&rows=32`)
    .then(r => r.json())
    .then(d => {
      if (d.status === 'ok' && d.hex_rows) {
        appData.hexRows = d.hex_rows;
        renderHexView();
        switchBottomTab('hex');
      }
    });
}

function inspectByteOffset(offsetHex) {
  document.getElementById('status-va').innerText = offsetHex;
  const path = appData.binaryPath || appData.currentBinaryPath;
  if (!path) return;
  fetch(`/api/inspect?path=${encodeURIComponent(path)}&offset=${encodeURIComponent(offsetHex)}`)
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
          ['Unix Timestamp', ins.unix_timestamp_iso],
          ['ASCII String', ins.ascii_string],
          ['Disassembly', (ins.disassembly_preview || []).join(' ; ')]
        ];
        container.innerHTML = fields.map(([k, v]) => `<div class="insp-row"><span class="insp-key">${escHtml(k)}</span><span class="insp-val" title="${escHtml(v)}">${escHtml(v)}</span></div>`).join('');
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

function renderMitigationsHUD() {
  const grid = document.getElementById('hud-grid');
  grid.innerHTML = '';
  for (const [title, info] of Object.entries(appData.mitigations || {})) {
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
  Array.from(linksLayer.querySelectorAll('path')).forEach(p => p.remove());

  const blocks = (appData.cfgBlocks && appData.cfgBlocks.length > 0) ? appData.cfgBlocks : [];
  document.getElementById('cfg-stats-badge').innerText = `(${blocks.length} blocks)`;
  const addrToBlock = {};
  blocks.forEach(b => { if (b.addr) addrToBlock[String(b.addr).toLowerCase()] = b; });

  blocks.forEach(b => {
    const nodeEl = document.createElement('div');
    nodeEl.className = 'cfg-node';
    nodeEl.style.left = (b.x || 120) + 'px';
    nodeEl.style.top = (b.y || 36) + 'px';
    let insnHTML = (b.insns || []).map(i => `
      <div class="cfg-insn" data-va="${escHtml(i.va || b.addr)}" onclick="event.stopPropagation(); syncHighlightAddress('${escHtml(i.va || b.addr)}')">
        <span class="cfg-va">${escHtml(i.va || '')}</span>
        <span class="cfg-mnem">${escHtml(i.mnem)}</span>
        <span class="cfg-ops" title="${escHtml(i.ops)}">${escHtml(i.ops)}</span>
      </div>
    `).join('');
    nodeEl.innerHTML = `<div class="cfg-node-hdr"><span>${escHtml(b.label)}</span><span>#${b.id || 0}</span></div><div class="cfg-node-body">${insnHTML}</div>`;
    nodeEl.onclick = () => syncHighlightAddress(b.addr);
    nodesLayer.appendChild(nodeEl);
  });

  blocks.forEach(b => {
    const srcH = 44 + ((b.insns || []).length * 19);
    (b.successors || []).forEach((succAddr, idx) => {
      const targetBlock = addrToBlock[String(succAddr).toLowerCase()];
      if (targetBlock) {
        const x1 = (b.x || 120) + 165, y1 = (b.y || 36) + srcH;
        const x2 = (targetBlock.x || 120) + 165, y2 = (targetBlock.y || 36);
        const color = idx === 0 ? '#22c55e' : '#ef4444';
        const marker = idx === 0 ? 'arrow-true' : 'arrow-false';
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        const midY = (y1 + y2) / 2;
        path.setAttribute('d', `M ${x1} ${y1} C ${x1} ${midY}, ${x2} ${midY}, ${x2} ${y2}`);
        path.setAttribute('stroke', color);
        path.setAttribute('stroke-width', '2');
        path.setAttribute('fill', 'none');
        path.setAttribute('marker-end', `url(#${marker})`);
        linksLayer.appendChild(path);
      }
    });
  });
}

/* Pan & Wheel Zoom for CFG Canvas */
function applyCfgTransform() {
  const vp = document.getElementById('cfg-viewport');
  vp.style.transform = `translate(${panX}px, ${panY}px) scale(${currentZoom})`;
}
function startCfgPan(e) {
  if (e.target.closest('.cfg-node') || e.target.closest('.graph-controls')) return;
  isPanning = true;
  panStartX = e.clientX - panX;
  panStartY = e.clientY - panY;
}
function moveCfgPan(e) {
  if (!isPanning) return;
  panX = e.clientX - panStartX;
  panY = e.clientY - panStartY;
  applyCfgTransform();
}
function endCfgPan() { isPanning = false; }
function wheelCfgZoom(e) {
  e.preventDefault();
  const factor = e.deltaY < 0 ? 1.12 : 0.89;
  currentZoom = Math.min(2.5, Math.max(0.25, currentZoom * factor));
  applyCfgTransform();
}
function zoomGraph(factor) {
  currentZoom = Math.min(2.5, Math.max(0.25, currentZoom * factor));
  applyCfgTransform();
}
function resetGraphZoom() {
  currentZoom = 1.0;
  panX = 0;
  panY = 0;
  applyCfgTransform();
}

function updateHoverByte(hexStr, decVal) {
  document.getElementById('status-byte').innerText = `${hexStr} (${decVal})`;
}

function filterSidebar() { renderSidebar(); }

/* Non-Blocking In-App Command Modal */
let activeModalSubmit = null;
function openActionModal(title, fieldsHtml, onSubmit) {
  document.getElementById('modal-title').innerText = title;
  document.getElementById('modal-fields').innerHTML = fieldsHtml;
  activeModalSubmit = onSubmit;
  document.getElementById('action-modal').classList.add('open');
  const firstInput = document.querySelector('#modal-fields input');
  if (firstInput) firstInput.focus();
  document.getElementById('modal-submit-btn').onclick = () => {
    if (activeModalSubmit) activeModalSubmit();
    closeActionModal();
  };
}
function closeActionModal() {
  document.getElementById('action-modal').classList.remove('open');
  activeModalSubmit = null;
}

function openPathModal() {
  openActionModal(
    'Open Binary Path on Server',
    `<div class="modal-field"><label>Server File Path (e.g. /bin/ls, /usr/bin/id):</label><input type="text" id="modal-path-in" value="${escHtml(appData.binaryPath || '/bin/ls')}"></div>`,
    () => {
      const p = document.getElementById('modal-path-in').value.trim();
      if (p) loadBinaryFromServer(p);
    }
  );
}

function openJumpModal() {
  openActionModal(
    'Jump to Virtual Address or Function',
    `<div class="modal-field"><label>Virtual Address (e.g. 0x4730):</label><input type="text" id="modal-jump-in" value="${escHtml(appData.activeFunctionVa || appData.entryPoint)}"></div>`,
    () => {
      const target = document.getElementById('modal-jump-in').value.trim();
      if (target) selectAndDecompileFunction(target);
    }
  );
}

function openRenameModal() {
  openActionModal(
    'Rename Function / Symbol (N)',
    `<div class="modal-field"><label>Target Address:</label><input type="text" id="modal-ren-addr" value="${escHtml(appData.activeFunctionVa || appData.entryPoint)}"></div>
     <div class="modal-field"><label>New Symbol Name:</label><input type="text" id="modal-ren-name" value="${escHtml(appData.activeFunctionName || 'decrypt_packet')}"></div>`,
    () => {
      const addr = document.getElementById('modal-ren-addr').value.trim();
      const val = document.getElementById('modal-ren-name').value.trim();
      if (!addr || !val) return;
      fetch('/api/annotate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action: 'rename', address: addr, value: val, path: appData.binaryPath })
      }).then(r => r.json()).then(d => {
        if (d.status === 'ok') {
          const fnEntry = appData.functions.find(f => String(f.addr).toLowerCase() === addr.toLowerCase());
          if (fnEntry) fnEntry.name = val;
          selectAndDecompileFunction(addr, val);
        }
      });
    }
  );
}

function openCommentModal() {
  const curVa = document.getElementById('status-va').innerText || appData.activeFunctionVa;
  openActionModal(
    'Add Analyst Comment (;)',
    `<div class="modal-field"><label>Instruction Address:</label><input type="text" id="modal-cmt-addr" value="${escHtml(curVa)}"></div>
     <div class="modal-field"><label>Comment:</label><input type="text" id="modal-cmt-text" value="Verified bounds check"></div>`,
    () => {
      const addr = document.getElementById('modal-cmt-addr').value.trim();
      const val = document.getElementById('modal-cmt-text').value.trim();
      fetch('/api/annotate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ action: 'comment', address: addr, value: val, path: appData.binaryPath })
      }).then(() => selectAndDecompileFunction(appData.activeFunctionVa, appData.activeFunctionName));
    }
  );
}

function openPatchModal() {
  openActionModal(
    'Live Binary Patcher',
    `<div class="modal-field"><label>File Offset (Hex):</label><input type="text" id="modal-patch-off" value="0x40"></div>
     <div class="modal-field"><label>Patch Operation:</label>
       <select id="modal-patch-op">
         <option value="nop">NOP Fill (0x90)</option>
         <option value="invert">Invert Conditional Branch (JE ↔ JNE)</option>
         <option value="ret0">Force Return 0 (xor eax, eax; ret)</option>
         <option value="ret1">Force Return 1 (mov eax, 1; ret)</option>
       </select>
     </div>`,
    async () => {
      const path = appData.binaryPath || appData.currentBinaryPath;
      if (!path) return;
      const off = document.getElementById('modal-patch-off').value.trim();
      const op = document.getElementById('modal-patch-op').value;
      const r = await fetch(`/api/patch?path=${encodeURIComponent(path)}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ offset: off, operation: op })
      });
      const d = await r.json();
      if (d.status === 'ok' && d.patched_path) {
        logConsole('LIVE BINARY PATCH APPLIED', JSON.stringify(d.transaction, null, 2));
        loadBinaryFromServer(d.patched_path);
      }
    }
  );
}

function debuggerStep() {
  fetch('/api/debug?action=step').then(r => r.json()).then(d => {
    document.getElementById('status-va').innerText = d.snapshot.rip;
    document.getElementById('dbg-rip-badge').innerText = 'RIP: ' + d.snapshot.rip;
    logConsole('DEBUGGER STEP (F7)', JSON.stringify(d.snapshot, null, 2));
  });
}
function debuggerContinue() {
  fetch('/api/debug?action=continue').then(r => r.json()).then(d => {
    document.getElementById('status-va').innerText = d.snapshot.rip;
    document.getElementById('dbg-rip-badge').innerText = 'RIP: ' + d.snapshot.rip;
    logConsole('DEBUGGER CONTINUE (F9)', JSON.stringify(d.snapshot, null, 2));
  });
}
function debuggerToggleBP() {
  const curVa = document.getElementById('status-va').innerText;
  fetch('/api/debug?action=bp&addr=' + encodeURIComponent(curVa)).then(r => r.json()).then(d => {
    document.getElementById('dbg-rip-badge').innerText = `BP @ ${curVa} (${d.snapshot.active_breakpoints.length} active)`;
  });
}

async function runCPUEmulation() {
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  const r = await fetch(`/api/emulate?path=${encodeURIComponent(path)}`);
  const d = await r.json();
  logConsole('DETERMINISTIC CPU EMULATION', JSON.stringify(d.emulation || d, null, 2));
}

async function runForceExecVisor() {
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  const r = await fetch(`/api/force-exec?path=${encodeURIComponent(path)}`);
  const d = await r.json();
  logConsole('UNDER-CONSTRAINED MICRO-VISOR (MULTI-PATH FORCE EXECUTION)', JSON.stringify(d.visor_report || d, null, 2));
}

async function runVulnAudit() {
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  const r = await fetch(`/api/vulns?path=${encodeURIComponent(path)}`);
  const d = await r.json();
  logConsole(`CWE VULNERABILITY AUDIT (Rating: ${d.risk_rating || 'CLEAN'})`, JSON.stringify(d.vulnerabilities || d, null, 2));
}

async function runYaraGenerator() {
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  const r = await fetch(`/api/yara?path=${encodeURIComponent(path)}`);
  const d = await r.json();
  const yaraText = (d.detection_bundle && d.detection_bundle.yara_rule_source) || JSON.stringify(d, null, 2);
  logConsole('GENERATED YARA & SIGMA DETECTION BUNDLE', yaraText);
}

async function execNativeRustCmd(cmd) {
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  const r = await fetch(`/api/native-rust?cmd=${encodeURIComponent(cmd)}&path=${encodeURIComponent(path)}`);
  const d = await r.json();
  logConsole(`NATIVE RUST ENGINE [reverse-forge-native ${cmd}]`, JSON.stringify(d, null, 2));
}

async function runNativeRustOmniAudit() {
  await execNativeRustCmd('omni-audit');
}

function exportCHeader() {
  window.open('/api/export-header', '_blank');
}

function runFullPipeline() {
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  setStatus('RUNNING 12-STAGE PIPELINE...', 'var(--warning)');
  fetch('/api/pipeline?path=' + encodeURIComponent(path))
    .then(r => r.json())
    .then(d => {
      if (d.status === 'ok') {
        logConsole('12-STAGE AUTONOMOUS AUDIT REPORT', d.markdown_report);
        setStatus('12-STAGE PIPELINE COMPLETE', 'var(--success)');
      }
    });
}

function uploadBinaryFile(file) {
  if (!file) return;
  setStatus(`UPLOADING ${file.name}...`, 'var(--warning)');
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
  // Check if query matches a discovered function name or hex address
  const fnMatch = appData.functions.find(f => f.name.toLowerCase() === q.toLowerCase() || String(f.addr).toLowerCase() === q.toLowerCase());
  if (fnMatch) {
    selectAndDecompileFunction(fnMatch.addr, fnMatch.name);
    return;
  }
  const path = appData.binaryPath || appData.currentBinaryPath || '/bin/ls';
  fetch(`/api/query?path=${encodeURIComponent(path)}&q=${encodeURIComponent(q)}`)
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok' && data.answer) {
        switchBottomTab('intel');
        renderCapabilitiesAndIntel(data.answer.results);
        logConsole(`SMART QUERY: "${q}" (${data.answer.intent_classified})`, data.answer.summary_answer);
      }
    });
}

function loadBinaryFromServer(path) {
  setStatus(`INDEXING ${path}...`, 'var(--warning)');
  fetch('/api/analyze?path=' + encodeURIComponent(path))
    .then(r => r.json())
    .then(data => {
      if (data.status === 'ok') {
        const d = data.dossier;
        appData.binaryPath = d.artifact;
        appData.currentBinaryPath = d.artifact;
        appData.format = d.format;
        appData.architecture = d.architecture;
        appData.entryPoint = d.entry_point;
        appData.activeFunctionName = d.active_function_name || 'main';
        appData.activeFunctionVa = d.active_function_va || d.entry_point;

        document.getElementById('binary-format-badge').innerText = `${d.format} · ${d.architecture}`;
        document.getElementById('active-func-badge').innerText = `${appData.activeFunctionName} @ ${appData.activeFunctionVa}`;
        document.getElementById('binary-name-label').innerText = `${d.artifact.split(/[\\/]/).pop()} (${(d.size_bytes / 1024).toFixed(1)} KB)`;

        appData.sections = (d.sections || []).map(s => ({
          name: s.name || '.sec',
          vaddr: s.virtual_address || s.address || '0x0',
          vsize: s.virtual_size || s.raw_size || s.size || 0,
          perms: s.executable ? 'R-X' : (s.writable ? 'RW-' : 'R--')
        }));
        appData.capabilities = d.capabilities || [];
        appData.xrefs = d.top_xrefs || [];
        appData.mitigations = d.mitigations || {};
        appData.cfgBlocks = d.cfg_blocks || [];
        appData.disassemblyLines = d.disassembly_lines || [];
        appData.hexRows = d.hex_rows || [];
        appData.pseudocode = (d.unified_decompiled_c || d.structured_goto_free_c || d.decompiled_entry_c || '').split('\n');
        appData.pcodeText = d.pcode_ssa_text || '';
        appData.esilText = d.rizin_esil_text || '';
        appData.vexText = d.angr_vex_text || '';

        const urls = (d.categorized_strings && d.categorized_strings.urls) || [];
        const paths = (d.categorized_strings && d.categorized_strings.file_paths) || [];
        const gen = (d.categorized_strings && d.categorized_strings.general) || [];
        appData.strings = [...urls, ...paths, ...gen].slice(0, 120).map((s, i) => ({ value: s, addr: '0x' + (0x1a000 + i * 16).toString(16) }));

        if (d.discovered_functions && d.discovered_functions.length > 0) {
          appData.functions = d.discovered_functions;
        } else {
          appData.functions = [{ name: "entry_main", addr: d.entry_point, size: 128, kind: "entry" }];
        }

        resetGraphZoom();
        renderAll();
        setStatus(`INDEXED ${appData.functions.length} FUNCTIONS · ACTIVE: ${appData.activeFunctionName}`, 'var(--success)');
      } else {
        setStatus('ERROR: ' + (data.error || 'Failed to load binary'), 'var(--danger)');
      }
    });
}

function renderAll() {
  document.getElementById('funcs-count').innerText = appData.functions.length;
  document.getElementById('strings-count').innerText = appData.strings.length;
  renderSidebar();
  renderLinearDisassembly();
  renderDecomp();
  renderHexView();
  renderCapabilitiesAndIntel();
  renderMitigationsHUD();
  renderCFGGraph();
}

window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeActionModal();
    return;
  }
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') {
    if (e.key === 'Enter' && document.getElementById('action-modal').classList.contains('open')) {
      document.getElementById('modal-submit-btn').click();
    }
    return;
  }
  if (e.code === 'Space') {
    e.preventDefault();
    const isCfg = document.getElementById('subtab-cfg').classList.contains('active');
    switchLeftPaneMode(isCfg ? 'disasm' : 'cfg');
  } else if (e.key === 'F5') {
    e.preventDefault();
    switchIrTab('c');
  } else if (e.key === 'g' || e.key === 'G') {
    e.preventDefault();
    openJumpModal();
  } else if (e.key === 'n' || e.key === 'N') {
    e.preventDefault();
    openRenameModal();
  } else if (e.key === ';') {
    e.preventDefault();
    openCommentModal();
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
    """Hardened, zero-dependency 4-Pane Synchronized REST API & Web GUI server for R3V3R53//F0RG3."""

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
                "active_engines": 118,
                "default_binary": self.default_binary_path,
            })
            return

        elif path == "/api/function":
            bin_path = query.get("path", [self.default_binary_path or ""])[0]
            addr_s = query.get("addr", [""])[0]
            if not bin_path or not os.path.exists(bin_path):
                self._json_response({"status": "error", "error": "Invalid binary path"}, status=400)
                return
            try:
                with open(bin_path, "rb") as f:
                    data = f.read(8 * 1024 * 1024)
                intel = BinaryIntelEngine(data, filepath=bin_path)
                idx = WholeBinaryFunctionIndexer(data, intel.metadata)
                target_va: Optional[int] = None
                if addr_s:
                    target_va = int(addr_s, 16) if addr_s.lower().startswith("0x") else int(addr_s, 10)
                bundle = idx.analyze_function(
                    target_va=target_va,
                    custom_renames=self.project_db.symbol_renames,
                    comments=self.project_db.comments,
                )
                self._json_response({"status": "ok", "function": asdict(bundle)})
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=500)
            return

        elif path == "/api/native-rust":
            cmd = query.get("cmd", ["doctor"])[0]
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            bin_exec = os.path.join(root, "rust_core", "bin", "reverse-forge-native")
            if not os.path.isfile(bin_exec):
                self._json_response({"status": "error", "error": "Native binary not compiled"}, status=404)
                return
            try:
                out = subprocess.check_output([bin_exec, cmd], text=True, timeout=5).strip()
                try:
                    parsed_out = json.loads(out)
                except Exception:
                    parsed_out = {"raw_output": out}
                self._json_response({"status": "ok", "command": cmd, "result": parsed_out})
            except Exception as e:
                self._json_response({"status": "error", "error": str(e)}, status=500)
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
        origin = self.headers.get("Origin", "")
        if origin and self._is_trusted_origin():
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


def start_gui_workbench(port: int = 8080, open_browser: bool = True, binary_path: Optional[str] = None) -> None:
    """Launch the local 4-Pane Synchronized GUI workbench server."""
    class ReusableServer(socketserver.TCPServer):
        allow_reuse_address = True

    if binary_path is None and os.path.exists("/bin/ls"):
        binary_path = "/bin/ls"

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
    print(f"  ║   9R0JE6T R10T // R3V3R53-F0RG3  4-Pane Synchronized Studio v27.0 ║")
    print(f"  ║   Whole-Binary Indexer · Per-Function CFG/C/IR · 55 Rust Modules   ║")
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
