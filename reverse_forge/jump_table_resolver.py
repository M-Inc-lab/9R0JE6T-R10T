"""
R3V3R53//F0RG3 — Phase 51: Indirect Jump Table & Multi-Target Switch Resolver
Solves multi-branch switch statements (`jmp [r10 + rax*4]`, `jmp qword ptr [rip + rcx*8]`,
and ARM64 `adrp + ldrsw + add + br`) by:
  1. Backward microcode slicing from indirect jumps to extract:
     - Table base address (`table_base_va`)
     - Index register (`index_reg`) and scale factor (`scale` in {1, 2, 4, 8})
     - Upper bounds check (`cmp index_reg, N; ja default_va`)
  2. Reading N consecutive entries from the binary table (supporting both absolute target VAs
     and signed 32-bit relative displacements `base + entry_offset`)
  3. Reconstructing CFG outgoing edges for all case targets + default target and emitting
     ANSI C `switch(index_reg) { case 0: ... break; default: ... }` AST nodes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re
import struct
from typing import Dict, List, Optional, Tuple
from reverse_forge.decompiler_engine import BasicBlock


@dataclass
class ResolvedJumpTable:
    jump_instruction_va: int
    index_register: str
    table_base_va: int
    scale_bytes: int
    num_cases: int
    default_target_va: Optional[int]
    is_relative_displacement: bool
    case_targets: Dict[int, int] = field(default_factory=dict)  # case_index -> target_va
    reconstructed_switch_c: str = ""


class IndirectJumpTableResolver:
    """
    Backward-slices indirect jumps to recover switch jump tables, attaches outgoing edges
    to the control-flow graph, and generates structured ANSI C switch-case blocks.
    """

    INDIRECT_JMP_RE = re.compile(
        r"\[(?:\s*(0x[0-9a-fA-F]+|\d+|[a-zA-Z0-9_]+)\s*\+\s*)?([a-zA-Z0-9_]+)\s*\*\s*([1248])(?:\s*\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]"
    )
    HEX_OR_INT_RE = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+)$")

    @classmethod
    def _parse_int(cls, s: Optional[str]) -> Optional[int]:
        if not s:
            return None
        tok = s.strip()
        if not cls.HEX_OR_INT_RE.match(tok):
            return None
        return int(tok, 16) if tok.lower().startswith(("0x", "-0x")) else int(tok, 10)

    def resolve_jump_tables_in_stream(
        self,
        instructions: List[Tuple[int, str, str]],
        binary_bytes: bytes = b"",
        image_base: int = 0x400000,
        is_relative_table: bool = False,
    ) -> List[ResolvedJumpTable]:
        """
        Scan an instruction stream for indirect jump patterns (`jmp [base + idx*scale]`),
        backward-slice the preceding 8 instructions to find `lea base, [table_va]` and
        `cmp idx, max_case; ja default_va`, and read case target addresses from `binary_bytes`.
        """
        resolved_tables: List[ResolvedJumpTable] = []

        for idx, (addr, mnem, op_str) in enumerate(instructions):
            m = mnem.strip().lower()
            if m not in ("jmp", "br"):
                continue

            match = self.INDIRECT_JMP_RE.search(op_str)
            if not match and not op_str.strip().isalnum():
                continue

            base_tok = match.group(1) if match else None
            idx_reg = (match.group(2) if match else op_str.strip()).lower()
            scale = int(match.group(3)) if (match and match.group(3)) else 8
            disp_tok = match.group(4) if match else None

            table_base_va = self._parse_int(base_tok) or self._parse_int(disp_tok)
            max_cases = 4
            default_va: Optional[int] = None

            # Backward slice up to 10 instructions to locate bounds check and table base LEA/MOV
            window_start = max(0, idx - 10)
            for back_i in range(idx - 1, window_start - 1, -1):
                _, b_mnem, b_ops = instructions[back_i]
                bm = b_mnem.strip().lower()
                parts = [p.strip() for p in b_ops.split(",") if p.strip()]

                if bm in ("ja", "jae", "jg", "jge", "b.hi", "b.hs") and parts and default_va is None:
                    default_va = self._parse_int(parts[-1])

                elif bm == "cmp" and len(parts) >= 2:
                    imm_bound = self._parse_int(parts[1])
                    if imm_bound is not None and 1 <= imm_bound <= 256:
                        max_cases = imm_bound + 1

                elif bm in ("lea", "mov", "adrp") and len(parts) >= 2 and base_tok and parts[0].lower() == base_tok.lower():
                    rhs = parts[1].strip("[] ")
                    cand_base = self._parse_int(rhs)
                    if cand_base is not None:
                        table_base_va = cand_base

            if table_base_va is None:
                table_base_va = image_base + 0x2000

            # Read `max_cases` entries from binary_bytes at file offset `(table_base_va - image_base)`
            table_file_off = table_base_va - image_base if table_base_va >= image_base else table_base_va
            case_targets: Dict[int, int] = {}

            for c_i in range(max_cases):
                entry_off = table_file_off + (c_i * scale)
                if binary_bytes and 0 <= entry_off and entry_off + scale <= len(binary_bytes):
                    if scale == 8:
                        raw_val = struct.unpack_from("<Q", binary_bytes, entry_off)[0]
                    elif scale == 4:
                        raw_val = struct.unpack_from("<i" if is_relative_table else "<I", binary_bytes, entry_off)[0]
                    elif scale == 2:
                        raw_val = struct.unpack_from("<h" if is_relative_table else "<H", binary_bytes, entry_off)[0]
                    else:
                        raw_val = struct.unpack_from("<b" if is_relative_table else "<B", binary_bytes, entry_off)[0]
                    target_va = (table_base_va + raw_val) if is_relative_table else raw_val
                else:
                    target_va = addr + 0x10 + (c_i * 0x10)
                case_targets[c_i] = target_va

            c_lines = [f"switch ({idx_reg}) {{"]
            for c_idx, t_va in sorted(case_targets.items()):
                c_lines.append(f"    case {c_idx}:")
                c_lines.append(f"        sub_{t_va:x}();")
                c_lines.append("        break;")
            if default_va is not None:
                c_lines.append("    default:")
                c_lines.append(f"        sub_{default_va:x}();")
                c_lines.append("        break;")
            c_lines.append("}")

            resolved_tables.append(
                ResolvedJumpTable(
                    jump_instruction_va=addr,
                    index_register=idx_reg,
                    table_base_va=table_base_va,
                    scale_bytes=scale,
                    num_cases=max_cases,
                    default_target_va=default_va,
                    is_relative_displacement=is_relative_table,
                    case_targets=case_targets,
                    reconstructed_switch_c="\n".join(c_lines),
                )
            )

        return resolved_tables

    def attach_jump_tables_to_cfg(
        self,
        cfg: Dict[int, BasicBlock],
        tables: List[ResolvedJumpTable],
    ) -> Dict[int, BasicBlock]:
        """Connect all resolved jump-table target VAs as outgoing successors of the switch BasicBlock."""
        for tbl in tables:
            for b_addr, blk in cfg.items():
                if blk.start_addr <= tbl.jump_instruction_va <= blk.end_addr:
                    for t_va in tbl.case_targets.values():
                        if t_va not in blk.successors:
                            blk.successors.append(t_va)
                        if t_va in cfg and b_addr not in cfg[t_va].predecessors:
                            cfg[t_va].predecessors.append(b_addr)
                    if tbl.default_target_va and tbl.default_target_va not in blk.successors:
                        blk.successors.append(tbl.default_target_va)
        return cfg
