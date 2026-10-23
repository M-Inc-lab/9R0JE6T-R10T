"""
R3V3R53//F0RG3 — Structural Binary & Patch Diffing Engine (§02.1, §02.5)
Compares two binary versions across sections, symbols, mitigations, and control-flow structure
to identify security patches, added/removed symbols, and modified functions.
"""

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from reverse_forge.correlation_engine import CorrelationEngine
from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.macho_analyzer import MachOAnalyzer
from reverse_forge.pe_analyzer import PEAnalyzer


@dataclass
class FunctionCFG:
    name: str
    basic_blocks: List[List[str]] = field(default_factory=list)
    edges: List[Tuple[int, int]] = field(default_factory=list)
    cyclomatic_complexity: int = 1
    normalized_mnemonics: List[str] = field(default_factory=list)


@dataclass
class CFGFunctionMatch:
    old_name: str
    new_name: str
    similarity_score: float
    structural_match: bool
    complexity_delta: int
    added_guard_blocks: int
    patch_description: str


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

    def build_cfg_from_instructions(self, instructions: List[str], function_name: str = "func") -> FunctionCFG:
        """Constructs basic blocks and control-flow edges from a sequence of assembly instructions."""
        blocks: List[List[str]] = []
        current_block: List[str] = []
        mnemonics: List[str] = []

        branch_mnemonics = {
            "jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
            "jz", "jnz", "js", "jns", "b", "beq", "bne", "bgt", "blt", "cbz", "cbnz"
        }
        term_mnemonics = {"ret", "retn", "bx lr"}

        for line in instructions:
            clean = line.strip()
            if not clean or clean.startswith(";") or clean.startswith("#"):
                continue

            # Check if this line is a label
            if clean.endswith(":") or clean.startswith(".L") or clean.startswith("loc_"):
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                current_block.append(clean)
                continue

            parts = clean.split(None, 1)
            op = parts[0].lower()
            mnemonics.append(op)
            current_block.append(clean)

            # End block on branch or return
            if op in branch_mnemonics or op in term_mnemonics:
                blocks.append(current_block)
                current_block = []

        if current_block:
            blocks.append(current_block)

        if not blocks:
            blocks = [["nop"]]
            mnemonics = ["nop"]

        # Synthesize edges (sequential fallthrough + branch targets)
        edges: List[Tuple[int, int]] = []
        for i in range(len(blocks) - 1):
            last_line = blocks[i][-1].strip()
            first_word = last_line.split()[0].lower() if last_line.split() else ""
            if first_word in term_mnemonics:
                continue
            edges.append((i, i + 1))
            # Conditional jump introduces an additional branch edge
            if first_word in branch_mnemonics and first_word != "jmp":
                edges.append((i, min(i + 2, len(blocks) - 1)))

        num_edges = len(edges)
        num_nodes = len(blocks)
        cyclomatic = max(1, num_edges - num_nodes + 2)

        return FunctionCFG(
            name=function_name,
            basic_blocks=blocks,
            edges=edges,
            cyclomatic_complexity=cyclomatic,
            normalized_mnemonics=mnemonics,
        )

    def compute_cfg_similarity(self, cfg_old: FunctionCFG, cfg_new: FunctionCFG) -> float:
        """Computes combined structural and mnemonic Dice similarity score in [0.0, 1.0]."""
        # Mnemonic multiset similarity
        m1 = cfg_old.normalized_mnemonics
        m2 = cfg_new.normalized_mnemonics
        if not m1 and not m2:
            return 1.0
        if not m1 or not m2:
            return 0.0

        from collections import Counter
        c1, c2 = Counter(m1), Counter(m2)
        intersection_count = sum((c1 & c2).values())
        mnemonic_dice = (2.0 * intersection_count) / (len(m1) + len(m2))

        # Structural complexity similarity
        max_blocks = max(len(cfg_old.basic_blocks), len(cfg_new.basic_blocks), 1)
        block_delta = abs(len(cfg_old.basic_blocks) - len(cfg_new.basic_blocks))
        structural_sim = max(0.0, 1.0 - (block_delta / max_blocks))

        return round(0.6 * mnemonic_dice + 0.4 * structural_sim, 3)

    def diff_functions_cfg(
        self,
        old_functions: Dict[str, List[str]],
        new_functions: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        Compares functions across two binary versions using CFG topology and mnemonic similarity.
        Detects security fixes such as added guard checks (cmp/test + branch) or removed sinks.
        """
        old_cfgs = {name: self.build_cfg_from_instructions(code, name) for name, code in old_functions.items()}
        new_cfgs = {name: self.build_cfg_from_instructions(code, name) for name, code in new_functions.items()}

        matches: List[CFGFunctionMatch] = []
        guard_indicators: List[str] = []

        all_names = sorted(set(old_cfgs.keys()) | set(new_cfgs.keys()))
        for name in all_names:
            if name in old_cfgs and name in new_cfgs:
                c_old = old_cfgs[name]
                c_new = new_cfgs[name]
                sim = self.compute_cfg_similarity(c_old, c_new)
                comp_delta = c_new.cyclomatic_complexity - c_old.cyclomatic_complexity

                # Detect added guard blocks: check if new version added 'cmp' or 'test' instructions
                old_guards = sum(1 for op in c_old.normalized_mnemonics if op in ("cmp", "test"))
                new_guards = sum(1 for op in c_new.normalized_mnemonics if op in ("cmp", "test"))
                added_guards = max(0, new_guards - old_guards)

                patch_desc = "Unchanged"
                if added_guards > 0:
                    patch_desc = f"Hardened: {added_guards} boundary guard check(s) added"
                    guard_indicators.append(f"Function `{name}`: {patch_desc} (Complexity delta: +{comp_delta})")
                elif comp_delta != 0 or sim < 0.99:
                    patch_desc = f"Modified control-flow (Similarity: {sim})"

                matches.append(CFGFunctionMatch(
                    old_name=name,
                    new_name=name,
                    similarity_score=sim,
                    structural_match=len(c_old.basic_blocks) == len(c_new.basic_blocks),
                    complexity_delta=comp_delta,
                    added_guard_blocks=added_guards,
                    patch_description=patch_desc,
                ))

        return {
            "total_functions_compared": len(matches),
            "matches": [
                {
                    "name": m.old_name,
                    "similarity": m.similarity_score,
                    "structural_match": m.structural_match,
                    "complexity_delta": m.complexity_delta,
                    "added_guards": m.added_guard_blocks,
                    "description": m.patch_description,
                }
                for m in matches
            ],
            "security_hardening_detected": len(guard_indicators) > 0,
            "security_guard_indicators": guard_indicators,
        }

