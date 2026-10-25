"""
R3V3R53//F0RG3 — Phase 62 & Phase 67: Unified 8-Pass End-to-End Decompilation Pipeline
Unifies all siloed disassembly, lifting, multi-block SSA optimization, deobfuscation,
control-flow structuring, FLIRT de-stripping, and struct-offset recovery engines into a
single cohesive pipeline (`UnifiedDecompilerPipeline`):
  Pass 1: Pure-Python Recursive-Descent Disassembly (`RecursiveDescentDisassembler`)
  Pass 2: Indirect Jump-Table & Multi-Target Switch Resolution (`IndirectJumpTableResolver`)
  Pass 3: FLIRT Compiler Runtime Library De-Stripping (`FLIRTRuntimeEngine`)
  Pass 4: Cross-Architecture Unified IL Lifting (`UnifiedILLifter`)
  Pass 5: Multi-Block Cytron SSA Construction, Constant Folding, Copy Prop & DSE (`SSALifterAndOptimizer`)
  Pass 6: Mixed Boolean-Arithmetic (MBA) Simplification & OLLVM Unflattening (`DeobfuscationEngine`)
  Pass 7: Post-Dominator Pattern-Independent Region Structuring (`ControlFlowRegionStructurer`)
          with inline `switch (reg) { case ... }` AST splicing
  Pass 8: Pointer-Offset Struct Layout Inference & `ptr->field_XX` AST Rewriting (`StructLayoutRecoveryEngine`)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from reverse_forge.recursive_disassembler import RecursiveDescentDisassembler
from reverse_forge.jump_table_resolver import IndirectJumpTableResolver
from reverse_forge.flirt_runtime_engine import FLIRTRuntimeEngine
from reverse_forge.unified_il_lifter import UnifiedILLifter
from reverse_forge.ssa_lifter import SSABasicBlock, SSALifterAndOptimizer
from reverse_forge.deobfuscation_engine import DeobfuscationEngine
from reverse_forge.decompiler_engine import MicroDecompilerEngine
from reverse_forge.region_structurer import ControlFlowRegionStructurer
from reverse_forge.struct_recovery_engine import StructLayoutRecoveryEngine


@dataclass
class UnifiedDecompilationResult:
    function_name: str
    entry_va: str
    architecture: str
    instructions_decoded: int
    jump_tables_resolved: int
    flirt_symbols_matched: List[str]
    ssa_phi_nodes: int
    ssa_constants_folded: int
    ssa_dead_stores_removed: int
    goto_count: int
    inferred_structs: List[Dict[str, Any]]
    cfg_blocks: List[Dict[str, Any]]
    final_c_code: str


class UnifiedDecompilerPipeline:
    """
    Executes the full 8-stage sovereign decompilation pipeline over raw code bytes,
    connecting every static analysis, multi-block SSA, and structuring pass end-to-end.
    """

    def __init__(self, arch: str = "x64"):
        raw = str(arch).lower()
        if "arm64" in raw or "aarch64" in raw:
            self.arch = "arm64"
        elif "riscv" in raw:
            self.arch = "riscv"
        elif "x86" in raw and "64" not in raw:
            self.arch = "x86"
        else:
            self.arch = "x64"

    def decompile_function_bytes(
        self,
        code_bytes: bytes,
        base_va: int = 0x401000,
        func_name: str = "entry_main",
        symbol_renames: Optional[Dict[str, str]] = None,
    ) -> UnifiedDecompilationResult:
        # Pass 1: Recursive-Descent Disassembly (with full ModR/M+SIB+disp memory decoding)
        disasm = RecursiveDescentDisassembler(arch=self.arch)
        decoded_map = disasm.disassemble_recursive(code_bytes[:4096], base_va=base_va)
        if not decoded_map:
            ins_tuples: List[Tuple[int, str, str]] = [(base_va, "ret", "")]
        else:
            ins_tuples = [
                (addr, ins.mnemonic, ins.op_str)
                for addr, ins in sorted(decoded_map.items())
            ]

        # Pass 2: Indirect Jump-Table Resolution
        jt_resolver = IndirectJumpTableResolver()
        j_tables = jt_resolver.resolve_jump_tables_in_stream(ins_tuples, binary_bytes=code_bytes, image_base=base_va)

        # Pass 3: FLIRT Library De-Stripping
        flirt = FLIRTRuntimeEngine()
        flirt_hits = flirt.scan_and_destrip(code_bytes, base_va=base_va)
        flirt_names = [f"{m.symbol_name}@{m.virtual_address}" for m in flirt_hits]
        if flirt_hits and flirt_hits[0].file_offset == 0 and func_name == "entry_main":
            func_name = flirt_hits[0].symbol_name

        # Build Control-Flow Graph and attach resolved Jump Tables
        m_decomp = MicroDecompilerEngine()
        cfg = m_decomp.build_cfg(ins_tuples)
        cfg = jt_resolver.attach_jump_tables_to_cfg(cfg, j_tables)

        # Pass 4 & 5: Multi-Block UnifiedIL Lifting & Cytron SSA Optimization across real CFG blocks
        lifter = UnifiedILLifter(target_arch=self.arch if self.arch in ("x86", "x64", "arm64", "mips") else "x64")
        ssa_blocks: Dict[int, SSABasicBlock] = {}
        sorted_addrs = sorted(cfg.keys()) if cfg else [base_va]
        addr_to_id = {addr: idx for idx, addr in enumerate(sorted_addrs)}

        if cfg:
            for b_addr, blk in sorted(cfg.items()):
                b_id = addr_to_id[b_addr]
                parsed_b = [
                    (mn, [p.strip() for p in ops.split(",") if p.strip()])
                    for _, mn, ops in blk.instructions
                ]
                b_uil = lifter.lift_block(parsed_b)
                ssa_blocks[b_id] = SSABasicBlock(
                    block_id=b_id,
                    instructions=b_uil,
                    predecessors=[addr_to_id[p] for p in blk.predecessors if p in addr_to_id],
                    successors=[addr_to_id[s] for s in blk.successors if s in addr_to_id],
                )
        else:
            parsed_for_uil = [
                (mn, [p.strip() for p in ops.split(",") if p.strip()])
                for _, mn, ops in ins_tuples
            ]
            ssa_blocks[0] = SSABasicBlock(block_id=0, instructions=lifter.lift_block(parsed_for_uil))

        ssa_opt = SSALifterAndOptimizer()
        ssa_rep = ssa_opt.optimize_ssa_blocks(ssa_blocks, entry_id=0)

        # Pass 6 & 7: Unflatten OLLVM and Structure Regions (Goto-Free)
        unflat = DeobfuscationEngine().unflatten_ollvm_cfg(cfg)
        struct_rep = ControlFlowRegionStructurer().structure_cfg(unflat.blocks, func_name=func_name)

        # Pass 8: Struct Layout Inference & Pointer-Offset AST Rewriting (`ptr->field_XX`)
        asm_and_c_lines = [f"{m} {o}".strip() for _, m, o in ins_tuples] + struct_rep.structured_c.splitlines()
        inferred_structs, _ = StructLayoutRecoveryEngine().recover_structs_from_code(
            asm_and_c_lines,
            func_addr=base_va,
        )
        _, rewritten_c = StructLayoutRecoveryEngine().recover_structs_from_code(
            struct_rep.structured_c,
            func_addr=base_va,
        )

        # Splice any resolved switch-case C blocks directly before the final closing brace of the function
        if j_tables:
            switch_blocks_str = "\n".join(
                "\n".join("    " + ln for ln in jt.reconstructed_switch_c.splitlines())
                for jt in j_tables
            )
            rbrace_idx = rewritten_c.rfind("}")
            if rbrace_idx != -1:
                rewritten_c = (
                    rewritten_c[:rbrace_idx]
                    + f"    /* Resolved Indirect Jump Table(s) ({len(j_tables)}) */\n"
                    + switch_blocks_str
                    + "\n"
                    + rewritten_c[rbrace_idx:]
                )

        header_parts: List[str] = [st.c_typedef for st in inferred_structs]
        full_c = ("\n\n".join(header_parts) + "\n\n" + rewritten_c).strip() if header_parts else rewritten_c

        if symbol_renames:
            for a_hex, new_sym in symbol_renames.items():
                norm_no_0x = a_hex.lower().lstrip("0x")
                full_c = full_c.replace(f"sub_{norm_no_0x}", new_sym)
                if a_hex.lower() == hex(base_va).lower():
                    full_c = full_c.replace(f"int64_t {func_name}(", f"int64_t {new_sym}(")

        # Serialize CFG blocks with hierarchical coordinates for live Web/Desktop rendering
        cfg_blocks_out: List[Dict[str, Any]] = []
        for idx, (b_addr, blk) in enumerate(sorted(unflat.blocks.items())):
            col = idx % 3
            row = idx // 3
            cfg_blocks_out.append({
                "id": idx,
                "addr": hex(b_addr),
                "label": f"loc_{b_addr:x}" if idx > 0 else f"{func_name}: {hex(b_addr)}",
                "x": 80 + col * 320,
                "y": 40 + row * 210,
                "insns": [{"mnem": m, "ops": o} for _, m, o in blk.instructions[:12]],
                "successors": [hex(s) for s in blk.successors],
            })

        return UnifiedDecompilationResult(
            function_name=func_name,
            entry_va=hex(base_va),
            architecture=self.arch,
            instructions_decoded=len(ins_tuples),
            jump_tables_resolved=len(j_tables),
            flirt_symbols_matched=flirt_names,
            ssa_phi_nodes=ssa_rep.phi_nodes_inserted,
            ssa_constants_folded=ssa_rep.constants_propagated,
            ssa_dead_stores_removed=ssa_rep.dead_stores_eliminated,
            goto_count=struct_rep.goto_count,
            inferred_structs=[asdict(s) for s in inferred_structs],
            cfg_blocks=cfg_blocks_out,
            final_c_code=full_c,
        )
