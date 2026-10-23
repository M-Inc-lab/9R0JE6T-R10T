"""
Unit tests for Phases 32–35 (v4.0 Apex Final Upgrade):
  - Phase 32: Cytron SSA Lifter, PHI-Node Placement, Constant Folding, Def-Use Copy Prop & DSE
  - Phase 33: Pattern-Independent Region-Based Control-Flow Structurer (Post-Dominators, Goto-Free C)
  - Phase 34: Declarative Datalog Fact Engine, Strided-Interval VSA, & Cross-Arch Interprocedural UIL Taint
  - Phase 35: 64-Bit Modular Bit-Vector Wrap-Around (CWE-190) & Relational Guard Verification + CLI Integration
"""

import json
import subprocess
import sys
import unittest

from reverse_forge.unified_il_lifter import UILInstruction, UnifiedILLifter
from reverse_forge.ssa_lifter import SSABasicBlock, SSALifterAndOptimizer
from reverse_forge.microcode_optimizer import MicrocodeOptimizer
from reverse_forge.decompiler_engine import BasicBlock, MicroDecompilerEngine
from reverse_forge.region_structurer import ControlFlowRegionStructurer
from reverse_forge.datalog_vsa_engine import DatalogVSAEngine, StridedInterval
from reverse_forge.fine_grain_taint_engine import FineGrainedTaintTracker, TaintTag
from reverse_forge.smt_solver_engine import PathConstraint, RelationalConstraint, SMTSolverEngine


class TestPhase32SSALifterAndOptimizer(unittest.TestCase):
    def test_dominators_and_phi_placement_on_diamond_cfg(self):
        """Verify Cytron dominance frontier inserts PHI node at diamond join block (Block 3)."""
        b0 = SSABasicBlock(
            block_id=0,
            instructions=[UILInstruction(opcode="ASSIGN", dest="rax", src1="1")],
            predecessors=[],
            successors=[1, 2],
        )
        b1 = SSABasicBlock(
            block_id=1,
            instructions=[UILInstruction(opcode="ASSIGN", dest="rax", src1="10")],
            predecessors=[0],
            successors=[3],
        )
        b2 = SSABasicBlock(
            block_id=2,
            instructions=[UILInstruction(opcode="ASSIGN", dest="rax", src1="20")],
            predecessors=[0],
            successors=[3],
        )
        b3 = SSABasicBlock(
            block_id=3,
            instructions=[UILInstruction(opcode="RET", dest="rax", src1="rax")],
            predecessors=[1, 2],
            successors=[],
        )
        ssa = SSALifterAndOptimizer()
        blocks, idom, df, phi_count = ssa.lift_to_ssa({0: b0, 1: b1, 2: b2, 3: b3}, entry_id=0)
        self.assertEqual(idom[3], 0)
        self.assertIn(3, df[1])
        self.assertIn(3, df[2])
        self.assertEqual(phi_count, 1)
        self.assertEqual(len(blocks[3].phi_nodes), 1)
        self.assertIn("PHI(", blocks[3].phi_nodes[0].raw_assembly)

    def test_ssa_constant_folding_copy_prop_and_dse(self):
        """Verify SSA constant folding, copy propagation, and dead-store elimination on UIL."""
        b0 = SSABasicBlock(
            block_id=0,
            instructions=[
                UILInstruction(opcode="ASSIGN", dest="rcx", src1="10"),
                UILInstruction(opcode="ASSIGN", dest="rdx", src1="rcx"),
                UILInstruction(opcode="ADD", dest="rax", src1="rdx", src2="32"),
                UILInstruction(opcode="ASSIGN", dest="rbx", src1="999"),  # Dead store
                UILInstruction(opcode="RET", dest="rax", src1="rax"),
            ],
        )
        opt = MicrocodeOptimizer()
        report = opt.optimize_uil_ssa({0: b0}, entry_id=0)
        self.assertGreaterEqual(report.constants_propagated, 2)
        self.assertGreaterEqual(report.dead_stores_eliminated, 2)
        remaining = report.blocks[0].instructions
        # Only the live return instruction (with folded constant 42) or final rax definition remains
        ret_ins = [i for i in remaining if i.opcode == "RET"][0]
        self.assertEqual(ret_ins.src1, "42")


class TestPhase33RegionStructurer(unittest.TestCase):
    def test_if_else_and_short_circuit_and_recovery_zero_gotos(self):
        """Verify post-dominator structuring recovers compound conditions and if/else with 0 gotos."""
        # Diamond CFG with short-circuit condition
        b1 = BasicBlock(
            start_addr=0x401000,
            end_addr=0x401004,
            instructions=[
                (0x401000, "cmp", "rdi, 0"),
                (0x401004, "je", "0x401020"),
            ],
            successors=[0x401020, 0x401008],
            predecessors=[],
        )
        b2 = BasicBlock(
            start_addr=0x401008,
            end_addr=0x40100C,
            instructions=[
                (0x401008, "cmp", "rsi, 10"),
                (0x40100C, "jg", "0x401010"),
            ],
            successors=[0x401010, 0x401020],
            predecessors=[0x401000],
        )
        b3 = BasicBlock(
            start_addr=0x401010,
            end_addr=0x401014,
            instructions=[
                (0x401010, "mov", "eax, 1"),
            ],
            successors=[0x401020],
            predecessors=[0x401008],
        )
        b4 = BasicBlock(
            start_addr=0x401020,
            end_addr=0x401024,
            instructions=[
                (0x401020, "ret", ""),
            ],
            successors=[],
            predecessors=[0x401000, 0x401008, 0x401010],
        )
        structurer = ControlFlowRegionStructurer()
        rep = structurer.structure_cfg({0x401000: b1, 0x401008: b2, 0x401010: b3, 0x401020: b4})
        self.assertEqual(rep.goto_count, 0)
        self.assertGreaterEqual(rep.compound_predicates, 1)
        self.assertIn("&&", rep.structured_c)
        self.assertNotIn("goto ", rep.structured_c)

    def test_switch_table_recovery(self):
        """Verify multi-way branch (>= 3 successors) structures into a C switch block."""
        b0 = BasicBlock(
            start_addr=0x1000,
            end_addr=0x1004,
            instructions=[(0x1000, "nop", "")],
            successors=[0x1010, 0x1020, 0x1030],
            predecessors=[],
        )
        b1 = BasicBlock(0x1010, 0x1014, [(0x1010, "mov", "eax, 10")], [0x1040], [0x1000])
        b2 = BasicBlock(0x1020, 0x1024, [(0x1020, "mov", "eax, 20")], [0x1040], [0x1000])
        b3 = BasicBlock(0x1030, 0x1034, [(0x1030, "mov", "eax, 30")], [0x1040], [0x1000])
        b4 = BasicBlock(0x1040, 0x1044, [(0x1040, "ret", "")], [], [0x1010, 0x1020, 0x1030])
        rep = ControlFlowRegionStructurer().structure_cfg(
            {0x1000: b0, 0x1010: b1, 0x1020: b2, 0x1030: b3, 0x1040: b4}
        )
        self.assertEqual(rep.recovered_switches, 1)
        self.assertIn("switch (arg1)", rep.structured_c)
        self.assertIn("case 0:", rep.structured_c)
        self.assertIn("case 2:", rep.structured_c)


class TestPhase34DatalogVSAAndInterproceduralUILTaint(unittest.TestCase):
    def test_vsa_strided_interval_indirect_jump_table_resolution(self):
        """Verify Balakrishnan & Reps StridedInterval resolves indirect jump table targets."""
        si_idx = StridedInterval(stride=1, lower=0, upper=3)
        si_scaled = si_idx.scale(8)
        self.assertEqual(si_scaled.stride, 8)
        self.assertEqual(si_scaled.enumerate_values(), [0, 8, 16, 24])

        insns = [
            (0x401000, "and", "rax, 3"),
            (0x401004, "jmp", "[0x402000 + rax*8]"),
        ]
        mem_table = {
            0x402000: 0x401100,
            0x402008: 0x401120,
            0x402010: 0x401140,
            0x402018: 0x401160,
        }
        vsa = DatalogVSAEngine()
        rep = vsa.analyze_instruction_facts(
            insns,
            initial_bounds={"rax": (0, 15)},
            memory_table=mem_table,
        )
        self.assertEqual(
            rep.indirect_call_targets[0x401004],
            [0x401100, 0x401120, 0x401140, 0x401160],
        )

    def test_arm64_and_interprocedural_uil_taint_summary(self):
        """Verify architecture-agnostic UIL taint tracking on ARM64 and interprocedural summaries."""
        lifter = UnifiedILLifter(target_arch="arm64")
        # Helper function ` sanitize_or_pass(x0) -> x0 ` that copies x0 to x0 and returns
        helper_uil = lifter.lift_block([
            ("add", ["x0", "x0", "8"]),
            ("ret", []),
        ])
        summary = FineGrainedTaintTracker.compute_function_summary(
            "passthrough_helper",
            helper_uil,
            calling_convention="arm64",
        )
        self.assertIn(0, summary.param_to_return_taint)

        # Caller on ARM64: taints x1, moves to x0, calls passthrough_helper, then calls system(x0)
        caller_uil = lifter.lift_block([
            ("mov", ["x0", "x1"]),
            ("bl", ["passthrough_helper"]),
            ("bl", ["system"]),
        ])
        tracker = FineGrainedTaintTracker(calling_convention="arm64")
        tracker.mark_tainted("x1", TaintTag.TAINTED_INPUT, "network_packet")
        violations = tracker.analyze_uil_stream(
            caller_uil,
            function_summaries={"passthrough_helper": summary},
        )
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].cwe_id, "CWE-78")
        self.assertEqual(violations[0].sink_name, "system")


class TestPhase35ModularWrapAndRelationalSMT(unittest.TestCase):
    def test_detect_64bit_modular_addition_wraparound_cwe190(self):
        """Verify 64-bit modular addition wraparound detection (size + 32 <= 512 wraps at 2^64 - 32)."""
        solver = SMTSolverEngine()
        res = solver.verify_modular_wrap_and_relational_guards(
            path_constraints=[PathConstraint(var="pkt_len", op="GT", value=0)],
            length_var="pkt_len",
            added_header_size=32,
            buffer_capacity=512,
            bit_width=64,
        )
        self.assertEqual(res["guard_status"], "MODULAR_WRAP_VULNERABLE")
        self.assertEqual(res["cwe_id"], "CWE-190")
        self.assertEqual(res["counterexample"]["wrapped_allocation_size"], 0)

    def test_relational_two_variable_guard_completeness(self):
        """Verify relational constraint (copy_len <= max_cap where max_cap <= 256) proves safety."""
        solver = SMTSolverEngine()
        res = solver.verify_modular_wrap_and_relational_guards(
            path_constraints=[
                PathConstraint(var="copy_len", op="GE", value=0),
                PathConstraint(var="max_cap", op="LE", value=256),
            ],
            relational_constraints=[
                RelationalConstraint(lhs_var="copy_len", op="LE", rhs_var="max_cap", rhs_offset=0),
            ],
            length_var="copy_len",
            added_header_size=0,
            buffer_capacity=256,
        )
        self.assertEqual(res["guard_status"], "GUARD_COMPLETE_RELATIONAL")
        self.assertIsNone(res["cwe_id"])

    def test_phase32_to_35_cli_commands_and_doctor(self):
        """Verify cli.py doctor reports 35 phases / 38 engines and ssa-optimize / vsa-analyze work."""
        doc = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "doctor"],
            capture_output=True, text=True, check=True,
        )
        doc_json = json.loads(doc.stdout)
        self.assertEqual(doc_json["phases_implemented"], 40)
        self.assertEqual(doc_json["internal_engines_count"], 43)

        ssa_run = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "ssa-optimize", "--asm", "mov rcx, 5; add rcx, 10; ret"],
            capture_output=True, text=True, check=True,
        )
        self.assertIn("constants_propagated", ssa_run.stdout)

        vsa_run = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "vsa-analyze", "--asm", "mov rax, 16; add rax, 32; ret"],
            capture_output=True, text=True, check=True,
        )
        self.assertIn("register_value_sets", vsa_run.stdout)


if __name__ == "__main__":
    unittest.main()
