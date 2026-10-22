"""
Tests for Phase 10: Federated Multi-Decompiler Consensus (IDA + Ghidra + Radare2),
SSA Symbolic Interval Bounds Verification, Structural Binary Diffing, and Semantic Recovery.
"""

import struct
import unittest

from reverse_forge.bindiff_engine import BinaryDiffEngine
from reverse_forge.ida_analyzer import IDAHeadlessAnalyzer
from reverse_forge.semantic_recovery import SemanticRecoveryEngine
from reverse_forge.symbolic_ir_engine import SSAOperation, SymbolicIREngine


class TestPhase10FederatedCapabilities(unittest.TestCase):
    def test_multi_decompiler_consensus(self):
        ghidra_mock = {
            "analysis": {
                "functions": [
                    {"name": "entry", "entry": "0x00401000"},
                    {"name": "FUN_00401050", "entry": "0x00401050"},
                ]
            }
        }
        ida_mock = {
            "analysis": {
                "functions": [
                    {"name": "start", "entry": "0x401000"},
                    {"name": "sub_401050", "entry": "0x401050"},
                    {"name": "sub_402000", "entry": "0x402000"},
                ]
            }
        }
        r2_mock = {
            "functions_sample": [
                {"name": "entry0", "offset": 0x401000},
            ]
        }

        consensus = IDAHeadlessAnalyzer.compute_decompiler_consensus(ghidra_mock, ida_mock, r2_mock)
        self.assertEqual(consensus["total_unique_functions"], 3)
        self.assertEqual(consensus["multi_engine_confirmed_count"], 2)
        self.assertEqual(consensus["single_engine_divergent_count"], 1)

    def test_symbolic_ir_interval_bounds_solver(self):
        engine = SymbolicIREngine()

        # Case 1: Unchecked input length written into 64-byte buffer -> PROVABLY_UNSAFE (CWE-787)
        unsafe_ops = [
            SSAOperation(op="INPUT", dest="len_0", src2_or_imm=1024),
            SSAOperation(op="BUFFER_WRITE", dest="buf_0", src1="len_0", buffer_capacity=64),
        ]
        res_unsafe = engine.evaluate_ssa_block(unsafe_ops)
        self.assertEqual(len(res_unsafe), 1)
        self.assertEqual(res_unsafe[0].status, "PROVABLY_UNSAFE")
        self.assertEqual(res_unsafe[0].cwe_id, "CWE-787")

        # Case 2: Input length clamped by branch guard ASSERT_LT(len_0, 64) -> PROVEN_SAFE
        safe_ops = [
            SSAOperation(op="INPUT", dest="len_0", src2_or_imm=1024),
            SSAOperation(op="ASSERT_LE", dest="len_0", src2_or_imm=64),
            SSAOperation(op="BUFFER_WRITE", dest="buf_0", src1="len_0", buffer_capacity=64),
        ]
        res_safe = engine.evaluate_ssa_block(safe_ops)
        self.assertEqual(len(res_safe), 1)
        self.assertEqual(res_safe[0].status, "PROVEN_SAFE")
        self.assertIsNone(res_safe[0].cwe_id)

    def test_structural_binary_diff_engine(self):
        # Construct two ELF64 headers with different section sizes
        elf_v1 = (
            b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
        )
        elf_v2 = (
            b"\x7fELF\x02\x01\x01" + b"\x00" * 9
            + struct.pack("<HHIQQQIHHHHHH", 3, 0x3E, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
        )
        differ = BinaryDiffEngine()
        diff = differ.diff_bytes(elf_v1, elf_v2)
        self.assertFalse(diff["identical"])
        self.assertIn("pie", diff["mitigation_changes"])
        self.assertFalse(diff["mitigation_changes"]["pie"]["old"])
        self.assertTrue(diff["mitigation_changes"]["pie"]["new"])

    def test_semantic_function_and_struct_recovery(self):
        pseudocode = """
        int sub_401200(void *ctx) {
            int s = socket(2, 1, 0);
            uint32_t port = *(uint32_t *)(ctx + 0x08);
            char *host = *(char **)(ctx + 0x10);
            bind(s, (struct sockaddr *)host, 16);
            listen(s, 5);
            return accept(s, 0, 0);
        }
        """
        rec = SemanticRecoveryEngine().recover_from_pseudocode("sub_401200", pseudocode)
        self.assertEqual(rec.confidence, "HIGH")
        self.assertIn("NetworkSocketListener", rec.suggested_name)
        self.assertEqual(len(rec.recovered_struct_fields), 2)
        self.assertEqual(rec.recovered_struct_fields[0]["offset"], "0x8")
        self.assertEqual(rec.recovered_struct_fields[1]["offset"], "0x10")


if __name__ == "__main__":
    unittest.main()
