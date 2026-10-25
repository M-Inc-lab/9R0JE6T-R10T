"""
R3V3R53//F0RG3 — Phase 59 & Phase 67: Headless Automation & Python Scripting Facade (`scripting_api.py`)
Provides an ergonomic, IDAPython / Binary-Ninja style Python API for headless automation and
Jupyter Notebook / Google Colab interactive analysis:
  - `ws = forge.open("binary.exe")` (or `forge.from_bytes(raw_bytes)`)
  - `ws.functions`            — List all discovered and de-stripped functions
  - `ws.decompile(addr)`      — Return structured goto-free ANSI C for the exact function at `addr`
  - `ws.vulnerabilities`      — Run automated CWE vulnerability & exploit primitive scan
  - `ws.xrefs_to(addr)`       — Query incoming cross-references to an address
  - `ws.xrefs_from(addr)`     — Query outgoing cross-references from an address
  - `ws.patch(offset, bytes)` — Apply reversible binary patches and live-refresh the workspace
  - `ws.undo_patch()`         — Revert last patch and live-refresh the workspace
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
from reverse_forge.project_workspace_db import ProjectWorkspaceDB
from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler
from reverse_forge.unified_decompiler_pipeline import UnifiedDecompilerPipeline


class ForgeScriptingWorkspace:
    """
    High-level headless scripting facade representing an opened binary workspace.
    """

    def __init__(self, binary_bytes: bytes, filepath: str = "<memory>"):
        self.filepath = filepath
        self.patcher = BinaryPatcherEngine(binary_bytes)
        self.intel = BinaryIntelEngine(bytes(self.patcher.working_bytes), filepath=filepath)
        self.project = ProjectWorkspaceDB(
            binary_name=os.path.basename(filepath),
        )
        self.flirt = FLIRTRuntimeEngine()
        self.disassembler = RecursiveDescentDisassembler()
        self._dossier: Optional[Dict[str, Any]] = None

    def _invalidate_cache(self) -> None:
        """Rebuild BinaryIntelEngine from current patched working bytes and invalidate cached dossier."""
        self.intel = BinaryIntelEngine(bytes(self.patcher.working_bytes), filepath=self.filepath)
        self._dossier = None

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

    @property
    def vulnerabilities(self) -> List[Dict[str, Any]]:
        """Return CWE-mapped vulnerability findings for the active binary."""
        return list(self.dossier.get("vulnerabilities", []))

    def decompile(self, address: Optional[int | str] = None) -> str:
        """
        Return structured goto-free ANSI C for the function at `address`
        (or entry point if `address` is omitted), applying any project symbol renames.
        """
        if address is None:
            raw_c = str(
                self.dossier.get("unified_decompiled_c")
                or self.dossier.get("structured_goto_free_c")
                or self.dossier.get("decompiled_entry_c")
                or ""
            )
            return self.project.apply_annotations_to_c_code(raw_c)

        va = int(str(address), 0) if isinstance(address, str) else int(address)
        file_off = self.intel._va_to_file_offset(va)
        raw_bytes = bytes(self.patcher.working_bytes)
        code_slice = raw_bytes[file_off : file_off + 1024] if 0 <= file_off < len(raw_bytes) else raw_bytes[:512]
        fn_name = self.project.symbol_renames.get(hex(va).lower(), f"sub_{va:x}")
        arch = str(self.dossier.get("architecture", "x64"))
        res = UnifiedDecompilerPipeline(arch=arch).decompile_function_bytes(
            code_slice,
            base_va=va,
            func_name=fn_name,
            symbol_renames=self.project.symbol_renames,
        )
        return self.project.apply_annotations_to_c_code(res.final_c_code)

    def rename_symbol(self, address: int | str, new_name: str) -> str:
        """Rename a function or address in the scripting workspace."""
        return self.project.rename_symbol(address, new_name)

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
        """Apply a reversible byte patch at `file_offset` and refresh live workspace state."""
        tx = self.patcher.apply_raw_patch(file_offset=file_offset, new_bytes=new_bytes, description=description)
        self._invalidate_cache()
        return asdict(tx)

    def undo_patch(self) -> Optional[Dict[str, Any]]:
        """Revert the most recent patch and refresh live workspace state."""
        tx = self.patcher.undo_last_patch()
        self._invalidate_cache()
        return asdict(tx) if tx else None

    def ask(self, query: str) -> Dict[str, Any]:
        """Execute a natural or structured query against the binary."""
        return asdict(self.intel.smart_query(query))

    def _repr_html_(self) -> str:
        """Render a rich dark-mode summary card inside Jupyter / Google Colab notebooks."""
        d = self.dossier
        fn_escaped = html.escape(os.path.basename(self.filepath))
        fmt_escaped = html.escape(f"{d['format']} ({d['architecture']})")
        sha_escaped = html.escape(d["sha256"][:24] + "...")
        c_escaped = html.escape(self.decompile()[:400])
        return (
            '<div style="background:#0a0e17;color:#f3f4f6;border:1px solid #1f2937;border-radius:8px;padding:14px;font-family:monospace;">'
            f'<div style="color:#38bdf8;font-weight:bold;font-size:14px;margin-bottom:8px;">⚡ R3V3R53//F0RG3 Workspace — {fn_escaped}</div>'
            f'<div style="font-size:12px;color:#9ca3af;margin-bottom:10px;">'
            f'Format: <b>{fmt_escaped}</b> | Size: <b>{d["size_bytes"]:,} B</b> | Entry: <b>{html.escape(str(d["entry_point"]))}</b> | SHA-256: <code>{sha_escaped}</code>'
            '</div>'
            f'<pre style="background:#111827;color:#a7f3d0;padding:10px;border-radius:6px;overflow-x:auto;font-size:11px;margin:0;">{c_escaped}</pre>'
            '</div>'
        )


def open_binary(filepath: str) -> ForgeScriptingWorkspace:
    """Open a binary file from disk into a `ForgeScriptingWorkspace`."""
    with open(filepath, "rb") as f:
        data = f.read()
    return ForgeScriptingWorkspace(data, filepath=os.path.abspath(filepath))


def from_bytes(raw_bytes: bytes, name: str = "<memory>") -> ForgeScriptingWorkspace:
    """Open an in-memory byte buffer into a `ForgeScriptingWorkspace`."""
    return ForgeScriptingWorkspace(raw_bytes, filepath=name)
