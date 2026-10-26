"""
R3V3R53//F0RG3 — Phase 78: Universal Layer-1 -> Layer-2 Bridge Exporter
(`tier2_bridge_exporter.py`)
Implements the Two-Layer Reverse Engineering Workflow:
  - Layer 1 (Reverse-Forge): Sub-200ms automated triage, CWE vulnerability sink detection,
    CAPA behavioral mapping, FLOSS/XOR string deobfuscation, FLIRT/PDB recovery, and C2 extraction.
  - Layer 2 (IDA Pro, Ghidra, Binary Ninja, x64dbg): Deep interactive manual reverse engineering.

This bridge exporter packages every Layer-1 finding into ready-to-run scripts and databases for:
  1. IDA Pro (`IDAPython` script coloring CWE sinks, renaming FLIRT/PDB functions, and commenting xrefs)
  2. Ghidra (`GhidraScript` creating Triage Bookmarks and Plate Comments at every flagged VA)
  3. Binary Ninja (`BinaryNinja` Python script tagging functions and annotating CWE/CAPA findings)
  4. x64dbg / x32dbg (`.dd64` / `.dd32` JSON debugger database with pre-populated labels, comments, and bookmarks)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional


@dataclass
class Layer2BridgePackage:
    target_artifact: str
    binary_sha256: str
    total_annotations_exported: int
    idapython_triage_script: str
    ghidra_triage_script: str
    binary_ninja_triage_script: str
    x64dbg_dd64_database_json: Dict[str, Any]


class Tier2BridgeExporter:
    """
    Exports all Layer-1 Reverse-Forge triage discoveries (capabilities, CWE sinks,
    deobfuscated strings, C2 indicators, symbol renames, and comments) into
    IDA Pro, Ghidra, Binary Ninja, and x64dbg formats.
    """

    def export_bridge_package(
        self,
        dossier: Dict[str, Any],
        symbol_renames: Optional[Dict[str, str]] = None,
        analyst_comments: Optional[Dict[str, str]] = None,
    ) -> Layer2BridgePackage:
        renames = dict(symbol_renames or {})
        comments = dict(analyst_comments or {})
        sha256 = str(dossier.get("sha256", ""))
        entry_va = str(dossier.get("entry_point", "0x401000"))
        image_base = str(dossier.get("image_base", "0x400000"))
        artifact = str(dossier.get("artifact", "target.bin"))

        # Automatically harvest triage findings into VA-indexed comments & bookmarks
        triage_notes: List[Dict[str, str]] = []
        for v in dossier.get("vulnerabilities", []):
            loc = str(v.get("location_va", entry_va))
            va = loc if loc.startswith("0x") else entry_va
            triage_notes.append({
                "va": va,
                "category": f"VULN_{v.get('cwe_id', 'CWE')}",
                "severity": str(v.get("severity", "HIGH")),
                "text": f"[{v.get('cwe_id')}] {v.get('title')} — {v.get('evidence')}",
            })

        for c in dossier.get("capabilities", []):
            triage_notes.append({
                "va": entry_va,
                "category": f"CAPA_{c.get('capability_id', 'CAP')}",
                "severity": str(c.get("severity", "MEDIUM")).upper(),
                "text": f"[CAPA {c.get('attck_id')}] {c.get('name')}: {', '.join(c.get('matched_indicators', [])[:3])}",
            })

        for x in dossier.get("top_xrefs", [])[:15]:
            if x.get("resolved_target_preview"):
                from_va = str(x.get("from_va", entry_va))
                comments.setdefault(from_va, f"Xref -> {x['resolved_target_preview']}")

        total_ann = len(renames) + len(comments) + len(triage_notes)

        # 1. IDAPython Triage Overlay Script
        ida_lines = [
            "# ============================================================================",
            f"# R3V3R53//F0RG3 Layer-1 -> Layer-2 IDAPython Triage Bridge",
            f"# Artifact: {artifact} (SHA-256: {sha256[:24]}...)",
            "# ============================================================================",
            "import idc",
            "import idaapi",
            "",
            "def apply_reverse_forge_layer1_triage():",
        ]
        for addr_hex, fn_name in sorted(renames.items()):
            ida_lines.append(f"    idc.set_name({addr_hex}, {json.dumps(fn_name)}, idc.SN_NOWARN)")
        for addr_hex, cmt in sorted(comments.items()):
            ida_lines.append(f"    idc.set_cmt({addr_hex}, {json.dumps(cmt)}, 1)")
        for idx, tn in enumerate(triage_notes):
            va_s = tn["va"] if tn["va"].startswith("0x") else "0x401000"
            ida_lines.append(f"    idc.set_cmt({va_s}, {json.dumps(tn['text'])}, 1)")
            if tn["severity"] in ("CRITICAL", "HIGH"):
                ida_lines.append(f"    idc.set_color({va_s}, idc.CIC_ITEM, 0x202060)  # Highlight high-risk sink")
        if total_ann == 0:
            ida_lines.append("    pass")
        ida_lines.extend([
            "",
            "if __name__ == '__main__':",
            "    apply_reverse_forge_layer1_triage()",
            f"    print('[+] Applied {total_ann} Reverse-Forge Layer-1 triage annotations to IDA Pro.')",
        ])

        # 2. Ghidra Python Triage Script
        ghidra_lines = [
            "# ============================================================================",
            "# R3V3R53//F0RG3 Layer-1 -> Layer-2 Ghidra Triage Bridge",
            "# @category ReverseForge.Triage",
            "# ============================================================================",
            "from ghidra.program.model.symbol import SourceType",
            "from ghidra.program.model.listing import CodeUnit",
            "",
            "def apply_layer1_triage():",
            "    fm = currentProgram.getFunctionManager()",
            "    listing = currentProgram.getListing()",
            "    bm = currentProgram.getBookmarkManager()",
        ]
        for addr_hex, fn_name in sorted(renames.items()):
            ghidra_lines.extend([
                f"    fn = fm.getFunctionAt(toAddr({json.dumps(addr_hex)}))",
                "    if fn is not None:",
                f"        fn.setName({json.dumps(fn_name)}, SourceType.USER_DEFINED)",
            ])
        for tn in triage_notes:
            va_s = tn["va"] if tn["va"].startswith("0x") else "0x401000"
            ghidra_lines.append(
                f"    bm.setBookmark(toAddr({json.dumps(va_s)}), 'Analysis', {json.dumps(tn['category'])}, {json.dumps(tn['text'])})"
            )
            ghidra_lines.append(
                f"    listing.setComment(toAddr({json.dumps(va_s)}), CodeUnit.PLATE_COMMENT, {json.dumps(tn['text'])})"
            )
        ghidra_lines.extend(["", "apply_layer1_triage()"])

        # 3. Binary Ninja Triage Script
        binja_lines = [
            "# ============================================================================",
            "# R3V3R53//F0RG3 Layer-1 -> Layer-2 Binary Ninja Triage Bridge",
            "# ============================================================================",
            "def apply_binja_triage(bv):",
        ]
        for addr_hex, fn_name in sorted(renames.items()):
            binja_lines.extend([
                f"    fn = bv.get_function_at({addr_hex})",
                "    if fn is not None:",
                f"        fn.name = {json.dumps(fn_name)}",
            ])
        for tn in triage_notes:
            va_s = tn["va"] if tn["va"].startswith("0x") else "0x401000"
            binja_lines.append(f"    bv.set_comment_at({va_s}, {json.dumps(tn['text'])})")
        if total_ann == 0:
            binja_lines.append("    pass")

        # 4. x64dbg / x32dbg JSON Database (.dd64 / .dd32)
        mod_name = artifact.replace("\\", "/").split("/")[-1].lower()
        base_int = int(image_base, 16) if image_base.startswith("0x") else 0x400000

        def _rva_hex(va_str: str) -> str:
            try:
                v = int(va_str, 16) if va_str.startswith("0x") else int(va_str, 10)
                rva = v - base_int if v >= base_int else v
                return f"0x{max(0, rva):X}"
            except Exception:
                return "0x1000"

        x64dbg_db = {
            "labels": [
                {"module": mod_name, "address": _rva_hex(a), "manual": True, "text": sym}
                for a, sym in sorted(renames.items())
            ],
            "comments": [
                {"module": mod_name, "address": _rva_hex(tn["va"]), "manual": True, "text": tn["text"]}
                for tn in triage_notes
            ] + [
                {"module": mod_name, "address": _rva_hex(a), "manual": True, "text": cmt}
                for a, cmt in sorted(comments.items())
            ],
            "bookmarks": [
                {"module": mod_name, "address": _rva_hex(tn["va"]), "manual": True}
                for tn in triage_notes
            ],
        }

        return Layer2BridgePackage(
            target_artifact=artifact,
            binary_sha256=sha256,
            total_annotations_exported=total_ann,
            idapython_triage_script="\n".join(ida_lines),
            ghidra_triage_script="\n".join(ghidra_lines),
            binary_ninja_triage_script="\n".join(binja_lines),
            x64dbg_dd64_database_json=x64dbg_db,
        )
