"""
R3V3R53//F0RG3 — Phase 50: Persistent `.rfdb` Project Database, Analyst Annotations & Interop Exporter
Modeled on IDA Pro `.idb`/`.i64`, Ghidra `.gpr`, and Binary Ninja `.bndb` project databases.
Allows reverse engineers to persist their analysis state across sessions and export interoperability artifacts:
  1. `rename_symbol(address, new_name)`     — Rename stripped functions (`sub_401000 -> decrypt_packet`)
  2. `set_comment(address, comment)`        — Attach inline analyst notes/annotations to any VA
  3. `add_bookmark(address, tag, note)`     — Bookmark key addresses (e.g. `CRYPTO_KEY`, `VULN_SINK`, `C2_URL`)
  4. `define_custom_struct(name, c_def)`    — Store custom C struct definitions inside the project
  5. `save_project(path)` / `load_project()`— Save and reload portable `.rfdb` JSON project databases
  6. `export_c_header()`                    — Export recovered structs and renamed function prototypes as a `.h` header
  7. `export_idapython_script()`            — Generate an IDAPython (`idaapi`/`idc`) script to import renames & comments into IDA Pro
  8. `export_ghidra_script()`               — Generate a Ghidra Python script to import renames & comments into Ghidra
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
import time
from typing import Any, Dict, List, Optional


@dataclass
class BookmarkEntry:
    address: str
    category: str
    description: str
    created_at: int = field(default_factory=lambda: int(time.time()))


class ProjectWorkspaceDB:
    """
    Portable `.rfdb` reverse-engineering project database storing symbol renames,
    analyst comments, bookmarks, and custom C structs with C-header/IDA/Ghidra export.
    """

    def __init__(self, binary_sha256: str = "", binary_name: str = "target.bin"):
        self.binary_sha256 = binary_sha256
        self.binary_name = binary_name
        self.symbol_renames: Dict[str, str] = {}        # norm_addr_hex -> new_symbol_name
        self.comments: Dict[str, str] = {}              # norm_addr_hex -> analyst_comment
        self.bookmarks: List[BookmarkEntry] = []
        self.custom_structs: Dict[str, str] = {}        # struct_name -> c_struct_source

    @staticmethod
    def _norm_addr(addr: str | int) -> str:
        if isinstance(addr, int):
            return hex(addr).lower()
        s = str(addr).strip().lower()
        return hex(int(s, 16)) if s.startswith("0x") else hex(int(s, 10))

    def rename_symbol(self, address: str | int, new_name: str) -> str:
        norm = self._norm_addr(address)
        sanitized = "".join(c if (c.isalnum() or c == "_") else "_" for c in new_name.strip())
        self.symbol_renames[norm] = sanitized
        return sanitized

    def set_comment(self, address: str | int, comment_text: str) -> None:
        norm = self._norm_addr(address)
        self.comments[norm] = comment_text.strip()

    def add_bookmark(self, address: str | int, category: str, description: str) -> BookmarkEntry:
        norm = self._norm_addr(address)
        entry = BookmarkEntry(address=norm, category=category.upper(), description=description.strip())
        self.bookmarks.append(entry)
        return entry

    def define_custom_struct(self, struct_name: str, c_struct_definition: str) -> None:
        self.custom_structs[struct_name.strip()] = c_struct_definition.strip()

    def apply_annotations_to_c_code(self, c_code: str) -> str:
        """Replace generic `sub_401000` names in decompiled C with the analyst's renamed symbols."""
        annotated = c_code
        for addr_hex, custom_name in self.symbol_renames.items():
            raw_hex = addr_hex[2:]
            annotated = annotated.replace(f"sub_{raw_hex}", custom_name)
            annotated = annotated.replace(addr_hex, f"{custom_name} /* {addr_hex} */")
        return annotated

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rfdb_version": "8.0.0-omniscient",
            "binary_name": self.binary_name,
            "binary_sha256": self.binary_sha256,
            "symbol_renames": dict(self.symbol_renames),
            "comments": dict(self.comments),
            "bookmarks": [asdict(b) for b in self.bookmarks],
            "custom_structs": dict(self.custom_structs),
        }

    def save_project(self, filepath: str) -> str:
        out_path = os.path.abspath(filepath)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return out_path

    @classmethod
    def load_project(cls, filepath: str) -> "ProjectWorkspaceDB":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        proj = cls(
            binary_sha256=data.get("binary_sha256", ""),
            binary_name=data.get("binary_name", "target.bin"),
        )
        proj.symbol_renames = dict(data.get("symbol_renames", {}))
        proj.comments = dict(data.get("comments", {}))
        proj.custom_structs = dict(data.get("custom_structs", {}))
        for b in data.get("bookmarks", []):
            proj.bookmarks.append(
                BookmarkEntry(
                    address=b["address"],
                    category=b["category"],
                    description=b["description"],
                    created_at=b.get("created_at", 0),
                )
            )
        return proj

    def export_c_header(self) -> str:
        """Export all custom structs and renamed function prototypes as a standard C `.h` header file."""
        lines = [
            "/* ==========================================================================",
            f" * Auto-Generated C Header by R3V3R53//F0RG3 Project Database",
            f" * Target Binary: {self.binary_name} (SHA-256: {self.binary_sha256 or 'N/A'})",
            " * ========================================================================== */",
            "#ifndef REVERSE_FORGE_RECOVERED_TYPES_H",
            "#define REVERSE_FORGE_RECOVERED_TYPES_H",
            "",
            "#include <stdint.h>",
            "#include <stddef.h>",
            "",
        ]
        if self.custom_structs:
            lines.append("/* --- Reconstructed Structures --- */")
            for s_name, s_def in sorted(self.custom_structs.items()):
                lines.append(s_def if s_def.endswith(";") else s_def + ";")
                lines.append("")

        if self.symbol_renames:
            lines.append("/* --- Renamed Function Prototypes --- */")
            for addr_hex, fn_name in sorted(self.symbol_renames.items()):
                comment = f" /* {self.comments[addr_hex]} */" if addr_hex in self.comments else ""
                lines.append(f"int64_t {fn_name}(int64_t arg1, int64_t arg2, int64_t arg3); /* VA: {addr_hex} */{comment}")
            lines.append("")

        lines.append("#endif /* REVERSE_FORGE_RECOVERED_TYPES_H */")
        return "\n".join(lines)

    def export_idapython_script(self) -> str:
        """Generate an IDAPython script (`idc.set_name`, `idc.set_cmt`) to synchronize findings with IDA Pro."""
        lines = [
            "# Auto-Generated IDAPython Synchronization Script from R3V3R53//F0RG3",
            "import idc",
            "",
            "def apply_reverse_forge_annotations():",
        ]
        for addr_hex, fn_name in sorted(self.symbol_renames.items()):
            lines.append(f"    idc.set_name({addr_hex}, {json.dumps(fn_name)}, idc.SN_NOWARN)")
        for addr_hex, cmt in sorted(self.comments.items()):
            lines.append(f"    idc.set_cmt({addr_hex}, {json.dumps(cmt)}, 0)")
        if not self.symbol_renames and not self.comments:
            lines.append("    pass")
        lines.extend([
            "",
            "if __name__ == '__main__':",
            "    apply_reverse_forge_annotations()",
            "    print('[+] Applied R3V3R53//F0RG3 annotations to IDA database.')",
        ])
        return "\n".join(lines)

    def export_ghidra_script(self) -> str:
        """Generate a Ghidra headless/GUI Python script to synchronize renames and comments into Ghidra."""
        lines = [
            "# Auto-Generated Ghidra Synchronization Script from R3V3R53//F0RG3",
            "# @category ReverseForge",
            "from ghidra.program.model.symbol import SourceType",
            "",
            "def apply_annotations():",
            "    fm = currentProgram.getFunctionManager()",
            "    listing = currentProgram.getListing()",
        ]
        for addr_hex, fn_name in sorted(self.symbol_renames.items()):
            lines.append(f"    addr = toAddr({json.dumps(addr_hex)})")
            lines.append("    fn = fm.getFunctionAt(addr)")
            lines.append("    if fn is not None:")
            lines.append(f"        fn.setName({json.dumps(fn_name)}, SourceType.USER_DEFINED)")
        for addr_hex, cmt in sorted(self.comments.items()):
            lines.append(f"    listing.setComment(toAddr({json.dumps(addr_hex)}), 0, {json.dumps(cmt)})")
        lines.extend([
            "",
            "apply_annotations()",
        ])
        return "\n".join(lines)
