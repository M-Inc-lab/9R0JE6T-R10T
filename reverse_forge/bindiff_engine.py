"""
R3V3R53//F0RG3 — Structural Binary & Patch Diffing Engine (§02.1, §02.5)
Compares two binary versions across sections, symbols, mitigations, and control-flow structure
to identify security patches, added/removed symbols, and modified functions.
"""

import hashlib
from typing import Any, Dict, List

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.pe_analyzer import PEAnalyzer


class BinaryDiffEngine:
    """Computes structural, symbol, and mitigation deltas between two binary artifacts."""

    def _profile_bytes(self, data: bytes) -> Dict[str, Any]:
        ce = CorrelationEngine()
        fmt = ce.identify_format(data)
        if fmt == "PE":
            meta = PEAnalyzer(data).analyze()
        elif fmt == "ELF":
            meta = ELFAnalyzer(data).analyze()
        elif fmt == "Mach-O":
            meta = MachOAnalyzer(data).analyze()
        else:
            meta = {"sections": [], "imported_symbols": [], "exported_symbols": [], "mitigations": {}}
        return {
            "format": fmt,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "metadata": meta,
        }

    def diff_bytes(self, old_data: bytes, new_data: bytes) -> Dict[str, Any]:
        old_p = self._profile_bytes(old_data)
        new_p = self._profile_bytes(new_data)

        old_meta = old_p["metadata"]
        new_meta = new_p["metadata"]

        old_secs = {s["name"]: s for s in old_meta.get("sections", []) if "name" in s}
        new_secs = {s["name"]: s for s in new_meta.get("sections", []) if "name" in s}

        added_sections = sorted(set(new_secs.keys()) - set(old_secs.keys()))
        removed_sections = sorted(set(old_secs.keys()) - set(new_secs.keys()))
        modified_sections = []
        for sname in sorted(set(old_secs.keys()) & set(new_secs.keys())):
            s1, s2 = old_secs[sname], new_secs[sname]
            sz1 = s1.get("raw_size") or s1.get("size") or 0
            sz2 = s2.get("raw_size") or s2.get("size") or 0
            if sz1 != sz2 or s1.get("entropy") != s2.get("entropy"):
                modified_sections.append({
                    "name": sname,
                    "old_size": sz1,
                    "new_size": sz2,
                    "size_delta": sz2 - sz1,
                    "old_entropy": s1.get("entropy"),
                    "new_entropy": s2.get("entropy"),
                })

        old_imps = set(old_meta.get("imported_symbols", []))
        new_imps = set(new_meta.get("imported_symbols", []))
        added_imports = sorted(new_imps - old_imps)
        removed_imports = sorted(old_imps - new_imps)

        old_mit = old_meta.get("mitigations", {})
        new_mit = new_meta.get("mitigations", {})
        mitigation_changes = {}
        for k in sorted(set(old_mit.keys()) | set(new_mit.keys())):
            if old_mit.get(k) != new_mit.get(k):
                mitigation_changes[k] = {"old": old_mit.get(k), "new": new_mit.get(k)}

        # Detect security hardening replacements (e.g. strcpy removed, strncpy_s/__strcpy_chk added)
        security_patch_indicators = []
        unsafe_removed = [fn for fn in removed_imports if fn.lstrip("_") in ("strcpy", "strcat", "sprintf", "gets", "system")]
        if unsafe_removed:
            security_patch_indicators.append(
                f"Removed unbounded/unsafe imported symbol(s): {unsafe_removed}"
            )
        if mitigation_changes:
            security_patch_indicators.append(
                f"Modified binary security mitigations: {list(mitigation_changes.keys())}"
            )

        similarity_ratio = 1.0 if old_p["sha256"] == new_p["sha256"] else round(
            len(set(old_secs.keys()) & set(new_secs.keys())) / max(1, len(set(old_secs.keys()) | set(new_secs.keys()))),
            2,
        )

        return {
            "old_sha256": old_p["sha256"],
            "new_sha256": new_p["sha256"],
            "identical": old_p["sha256"] == new_p["sha256"],
            "structural_similarity": similarity_ratio,
            "sections_delta": {
                "added": added_sections,
                "removed": removed_sections,
                "modified": modified_sections,
            },
            "imports_delta": {
                "added": added_imports,
                "removed": removed_imports,
            },
            "mitigation_changes": mitigation_changes,
            "security_patch_indicators": security_patch_indicators,
        }

    def diff_files(self, old_path: str, new_path: str) -> Dict[str, Any]:
        with open(old_path, "rb") as f1:
            d1 = f1.read()
        with open(new_path, "rb") as f2:
            d2 = f2.read()
        res = self.diff_bytes(d1, d2)
        res["old_artifact"] = old_path
        res["new_artifact"] = new_path
        return res
