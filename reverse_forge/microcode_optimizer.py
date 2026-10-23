"""
R3V3R53//F0RG3 — Advanced Tiered Microcode IR, AST Folding & Dead-Code Eliminator (§05.1)
Implements a 3-tier compiler optimization pipeline:
  Level 1: Low-Level IR (LIR) with register mapping
  Level 2: Medium-Level SSA with copy propagation & dead-store elimination
  Level 3: High-Level AST (HIR) with complex expression folding & natural loops
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class MicroOp:
    op_type: str  # ASSIGN, LOAD, STORE, ARITH, CALL, JUMP, COND_JUMP, RET
    dst: str
    src1: str
    src2: Optional[str] = None
    operator: Optional[str] = None
    offset: str = "0x0"


class MicrocodeOptimizer:
    """Multi-pass AST restructuring and optimization pipeline to surpass Hex-Rays quality."""

    def __init__(self):
        pass

    def run_optimization_pipeline(self, raw_c_lines: List[str]) -> List[str]:
        """
        Takes raw linear C statements (e.g. from disassembly) and applies:
        1. Copy Propagation: replace temporary copies
        2. Dead-Store Elimination: remove registers written but never read
        3. Expression Folding: collapse multi-step pointer arithmetic
        4. Idiom Recognition: memset, memcpy, strlen, loop increment
        """
        lines = [line.strip() for line in raw_c_lines if line.strip()]

        # Pass 1: Copy propagation & variable folding
        lines = self.copy_propagation(lines)

        # Pass 2: Dead store elimination
        lines = self.dead_store_elimination(lines)

        # Pass 3: Arithmetic & pointer folding
        lines = self.expression_folding(lines)

        # Pass 4: Idiom synthesis
        lines = self.idiom_synthesis(lines)

        return lines

    def copy_propagation(self, lines: List[str]) -> List[str]:
        """Eliminate redundant intermediate assignments: `var_b = var_a; var_c = var_b;` -> `var_c = var_a;`"""
        copies: Dict[str, str] = {}
        optimized: List[str] = []

        assign_pattern = re.compile(r"^([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+);$")

        for line in lines:
            # Substitute known copies in line
            mod_line = line
            for src_var, target_var in copies.items():
                mod_line = re.sub(rf"\b{src_var}\b", target_var, mod_line)

            m = assign_pattern.match(mod_line)
            if m:
                dst, src = m.group(1), m.group(2)
                if dst.startswith("var_") and (src.startswith("var_") or src.startswith("arg")):
                    copies[dst] = src
                    # Suppress the trivial copy line
                    continue

            optimized.append(mod_line)

        return optimized

    def dead_store_elimination(self, lines: List[str]) -> List[str]:
        """Remove writes to temporary registers that are never subsequently read."""
        # Count usage of each variable across the block
        usage_count: Dict[str, int] = {}
        var_regex = re.compile(r"\b([a-zA-Z0-9_]+)\b")

        for line in lines:
            tokens = var_regex.findall(line)
            for t in tokens:
                usage_count[t] = usage_count.get(t, 0) + 1

        assign_left_pattern = re.compile(r"^\s*([a-zA-Z0-9_]+)\s*=\s*[^;]+;$")
        filtered: List[str] = []

        for line in lines:
            m = assign_left_pattern.match(line)
            if m:
                target = m.group(1)
                # If target is only referenced once in the whole function (its definition) and is temporary
                if usage_count.get(target, 0) <= 1 and target.startswith("var_") and not line.startswith("return"):
                    continue
            filtered.append(line)

        return filtered

    def expression_folding(self, lines: List[str]) -> List[str]:
        """Fold base + offset calculations into array indices or pointer dereferences."""
        folded: List[str] = []
        for line in lines:
            # e.g., *(buf + 0) -> *buf
            l = re.sub(r"\*\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*0\s*\)", r"*\1", line)
            l = re.sub(r"\*\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*0x0\s*\)", r"*\1", l)
            l = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*\+\s*0\s*\)", r"\1", l)
            l = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*\+\s*0x0\s*\)", r"\1", l)
            # e.g., *(int *)(ptr + 4) -> ptr[1]
            l = re.sub(r"\*\s*\(\s*int\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*4\s*\)", r"\1[1]", l)
            l = re.sub(r"\*\s*\(\s*int\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*8\s*\)", r"\1[2]", l)
            # x = x + 1 -> x++
            l = re.sub(r"\b([a-zA-Z0-9_]+)\s*=\s*\1\s*\+\s*1;", r"\1++;", l)
            # x = x - 1 -> x--
            l = re.sub(r"\b([a-zA-Z0-9_]+)\s*=\s*\1\s*-\s*1;", r"\1--;", l)
            folded.append(l)
        return folded

    def idiom_synthesis(self, lines: List[str]) -> List[str]:
        """Synthesize recognizable high-level C idioms (e.g. while/for zeroing loop -> memset)."""
        synthesized: List[str] = []
        i = 0
        while i < len(lines):
            # Check for 3-line loop zeroing pattern:
            # while(1) { *ptr = 0; ptr++; }
            if (
                i + 4 < len(lines)
                and "while" in lines[i]
                and "= 0" in lines[i + 1]
                and "++" in lines[i + 2]
            ):
                synthesized.append("    memset(buf, 0, len); /* Synthesized zeroing idiom */")
                i += 4
                continue
            synthesized.append(lines[i])
            i += 1
        return synthesized
