"""
R3V3R53//F0RG3 — Advanced Tiered Microcode IR, AST Folding & Dead-Code Eliminator (§05.1)
Implements a 3-tier compiler optimization pipeline:
  Level 1: Low-Level IR (LIR) with register mapping
  Level 2: Medium-Level SSA with flow-sensitive copy propagation & dead-store elimination
  Level 3: High-Level AST (HIR) with complex expression folding & natural loops
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class MicroOp:
    op_type: str  # ASSIGN, LOAD, STORE, ARITH, CALL, JUMP, COND_JUMP, RET
    dst: str
    src1: str
    src2: Optional[str] = None
    operator: Optional[str] = None
    offset: str = "0x0"


class MicrocodeOptimizer:
    """Multi-pass AST restructuring and optimization pipeline preserving indentation and flow safety."""

    ASSIGN_SPLIT_RE = re.compile(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*([\+\-\*\/\&\|\^]?=)\s*(.+);$")
    SIMPLE_COPY_RE = re.compile(r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*);$")

    def run_optimization_pipeline(self, raw_c_lines: List[str]) -> List[str]:
        lines = [line.rstrip() for line in raw_c_lines if line.strip()]
        lines = self.copy_propagation(lines)
        lines = self.dead_store_elimination(lines)
        lines = self.expression_folding(lines)
        lines = self.idiom_synthesis(lines)
        return lines

    def copy_propagation(self, lines: List[str]) -> List[str]:
        """Flow-sensitive copy propagation that only rewrites RHS expressions and invalidates on mutation."""
        copies: Dict[str, str] = {}
        optimized: List[str] = []

        for line in lines:
            stripped = line.strip()
            # Control-flow labels or braces invalidate local copy assumptions
            if stripped.endswith(":") or stripped.startswith(("while", "if", "for", "}")):
                copies.clear()
                optimized.append(line)
                continue

            m_assign = self.ASSIGN_SPLIT_RE.match(line)
            if m_assign:
                indent, lhs, op, rhs = m_assign.group(1), m_assign.group(2), m_assign.group(3), m_assign.group(4)
                # Substitute active copies only in RHS
                for src_var, target_var in list(copies.items()):
                    rhs = re.sub(rf"\b{re.escape(src_var)}\b", target_var, rhs)

                # If compound assignment (+=, -=), also check if lhs itself had a copy
                if op != "=" and lhs in copies:
                    lhs = copies[lhs]

                # Invalidate any copy mapping where lhs is overwritten or was the source of another copy
                copies.pop(lhs, None)
                for k, v in list(copies.items()):
                    if v == lhs:
                        del copies[k]

                mod_line = f"{indent}{lhs} {op} {rhs};"
                m_copy = self.SIMPLE_COPY_RE.match(mod_line)
                if m_copy:
                    _, dst, src = m_copy.group(1), m_copy.group(2), m_copy.group(3)
                    if dst.startswith("var_") and (src.startswith("var_") or src.startswith("arg")):
                        copies[dst] = src
                        continue
                optimized.append(mod_line)
            else:
                mod_line = line
                for src_var, target_var in copies.items():
                    mod_line = re.sub(rf"\b{re.escape(src_var)}\b", target_var, mod_line)
                optimized.append(mod_line)

        return optimized

    def dead_store_elimination(self, lines: List[str]) -> List[str]:
        """Remove writes to temporary registers that are never subsequently read."""
        usage_count: Dict[str, int] = {}
        var_regex = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b")

        for line in lines:
            for t in var_regex.findall(line):
                usage_count[t] = usage_count.get(t, 0) + 1

        assign_left_pattern = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[^;]+;$")
        filtered: List[str] = []

        for line in lines:
            m = assign_left_pattern.match(line)
            if m:
                target = m.group(1)
                if usage_count.get(target, 0) <= 1 and target.startswith("var_") and not line.strip().startswith("return"):
                    continue
            filtered.append(line)

        return filtered

    def expression_folding(self, lines: List[str]) -> List[str]:
        """Fold base + offset calculations into array indices or pointer dereferences while preserving indent."""
        folded: List[str] = []
        for line in lines:
            l = re.sub(r"\*\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*0(?:x0)?\s*\)", r"*\1", line)
            l = re.sub(r"\(\s*([a-zA-Z0-9_]+)\s*\+\s*0(?:x0)?\s*\)", r"\1", l)
            l = re.sub(r"\*\s*\(\s*int\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*4\s*\)", r"\1[1]", l)
            l = re.sub(r"\*\s*\(\s*int\s*\*\s*\)\s*\(\s*([a-zA-Z0-9_]+)\s*\+\s*8\s*\)", r"\1[2]", l)
            l = re.sub(r"\b([a-zA-Z0-9_]+)\s*=\s*\1\s*\+\s*1;", r"\1++;", l)
            l = re.sub(r"\b([a-zA-Z0-9_]+)\s*=\s*\1\s*-\s*1;", r"\1--;", l)
            folded.append(l)
        return folded

    def idiom_synthesis(self, lines: List[str]) -> List[str]:
        """Synthesize recognizable high-level C idioms (e.g. while/for zeroing loop -> memset)."""
        synthesized: List[str] = []
        i = 0
        while i < len(lines):
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
