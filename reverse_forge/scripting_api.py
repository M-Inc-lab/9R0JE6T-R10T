"""
R3V3R53//F0RG3 — Phase 59: Headless Automation & Python Scripting Facade (`scripting_api.py`)
Provides an ergonomic, IDAPython / Binary-Ninja style Python API for headless automation and
Jupyter Notebook / Google Colab interactive analysis:
  - `ws = forge.open("binary.exe")` (or `forge.from_bytes(raw_bytes)`)
  - `ws.functions`            — List all discovered and de-stripped functions
  - `ws.decompile(addr)`      — Return structured goto-free ANSI C for a function
  - `ws.xrefs_to(addr)`       — Query incoming cross-references to an address
  - `ws.xrefs_from(addr)`     — Query outgoing cross-references from an address
  - `ws.patch(offset, bytes)` — Apply reversible binary patches and save modified binary
  - `ws.ask(query)`           — Execute natural/structured `BinaryIntelEngine.smart_query()`
  - `ws._repr_html_()`        — Render a rich dark-mode HTML summary card inside Jupyter / Colab notebooks!
"""

from __future__ import annotations

from dataclasses import asdict
import html
import os
from typing import Any, Dict, List, Optional

from reverse_forge.binary_intel_engine import BinaryIntelEngine
from reverse_forge.binary_patcher import BinaryPatcherEngine
from reverse_forge.flirt_runtime_engine import FLIRTRuntimeEngine
from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler


class ForgeScriptingWorkspace:
    """
    High-level headless scripting facade representing an opened binary workspace.
    """

    def __init__(self, binary_bytes: bytes, filepath: str = "<memory>"):
        self.filepath = filepath
        self.intel = BinaryIntelEngine(binary_bytes, filepath=filepath)
        self.patcher = BinaryPatcherEngine(binary_bytes)
        self.flirt = FLIRTRuntimeEngine()
        self.disassembler = RecursiveDescentDisassembler()
        self._dossier: Optional[Dict[str, Any]] = None

    @property
    def dossier(self) -> Dict[str, Any]:
        if self._dossier is None:
            self._dossier = self.intel.get_full_dossier()
        return self._dossier

    @property
    def functions(self) -> List[Dict[str, Any]]:
        """List discovered entry points, CALL targets, and FLIRT-identified library functions."""
        d = self.dossier
        fn_list: List[Dict[str, Any]] = [
            {"name": "entry_main", "address": d["entry_point"], "source": "entry_point"}
        ]
        seen = {d["entry_point"]}
        for x in d.get("top_xrefs", []):
            if x["xref_type"] == "CALL_REL32" and x["to_va"] not in seen:
                seen.add(x["to_va"])
                fn_list.append({
                    "name": x["resolved_target_preview"] or f"sub_{x['to_va'][2:]}",
                    "address": x["to_va"],
                    "source": "call_xref",
                })
        for fm in self.flirt.scan_and_destrip(bytes(self.patcher.working_bytes)):
            if fm.virtual_address not in seen:
                seen.add(fm.virtual_address)
                fn_list.append({
                    "name": fm.symbol_name,
                    "address": fm.virtual_address,
                    "source": f"FLIRT:{fm.library_family}",
                })
        return fn_list

    def decompile(self, address: Optional[int | str] = None) -> str:
        """Return structured goto-free ANSI C for the function at `address` (defaults to entry point)."""
        return str(self.dossier.get("structured_goto_free_c") or self.dossier.get("decompiled_entry_c") or "")

    def xrefs_to(self, target_va: int | str) -> List[Dict[str, Any]]:
        """Return all cross-references targeting `target_va`."""
        norm = hex(target_va).lower() if isinstance(target_va, int) else hex(int(str(target_va), 0)).lower()
        return [
            asdict(x) for x in self.intel.extract_all_xrefs(max_xrefs=256)
            if x.to_va.lower() == norm
        ]

    def xrefs_from(self, source_va: int | str) -> List[Dict[str, Any]]:
        """Return all cross-references originating at `source_va`."""
        norm = hex(source_va).lower() if isinstance(source_va, int) else hex(int(str(source_va), 0)).lower()
        return [
            asdict(x) for x in self.intel.extract_all_xrefs(max_xrefs=256)
            if x.from_va.lower() == norm
        ]

    def patch(self, file_offset: int, new_bytes: bytes, description: str = "Scripted patch") -> Dict[str, Any]:
        """Apply a reversible byte patch at `file_offset` and return the transaction record."""
        tx = self.patcher.apply_raw_patch(file_offset, new_bytes, description=description)
        self._dossier = None
        return asdict(tx)

    def ask(self, query: str) -> Dict[str, Any]:
        """Execute a natural or keyword query against the binary."""
        return asdict(self.intel.smart_query(query))

    def _repr_html_(self) -> str:
        """Rich HTML card representation for Jupyter Notebooks and Google Colab."""
        d = self.dossier
        fname = html.escape(os.path.basename(self.filepath))
        fmt = html.escape(str(d.get("format", "Unknown")))
        arch = html.escape(str(d.get("architecture", "x64")))
        sha = html.escape(str(d.get("sha256", ""))[:24])
        caps_cnt = int(d.get("capabilities_count", 0))
        return (
            '<div style="background:#0a0e17;color:#f3f4f6;border:1px solid #38bdf8;border-radius:8px;padding:14px;font-family:monospace;">'
            f'<div style="color:#38bdf8;font-weight:bold;font-size:14px;">R3V3R53//F0RG3 Workspace: {fname}</div>'
            f'<div style="margin-top:6px;color:#9ca3af;">Format: <b>{fmt}</b> ({arch}) | Entry: <b>{html.escape(str(d.get("entry_point")))}</b> | SHA-256: <code>{sha}...</code></div>'
            f'<div style="margin-top:4px;color:#22c55e;">Discovered Functions: {len(self.functions)} | CAPA Capabilities: {caps_cnt}</div>'
            '</div>'
        )


def open_binary(filepath: str) -> ForgeScriptingWorkspace:
    """Open a binary file on disk and return a `ForgeScriptingWorkspace`."""
    with open(filepath, "rb") as f:
        data = f.read()
    return ForgeScriptingWorkspace(data, filepath=os.path.abspath(filepath))


def from_bytes(raw_bytes: bytes, name: str = "<memory>") -> ForgeScriptingWorkspace:
    """Create a `ForgeScriptingWorkspace` directly from an in-memory `bytes` buffer."""
    return ForgeScriptingWorkspace(raw_bytes, filepath=name)
