"""
Tests for Phase 23 & Phase 24: Fine-Grained Assembly Taint Tracker & CFG Patch Diffing Engine.
"""

import unittest
from reverse_forge.fine_grain_taint_engine import FineGrainedTaintTracker, TaintTag
from reverse_forge.bindiff_engine import BinaryDiffEngine, FunctionCFG


class TestPhase23FineGrainedTaint(unittest.TestCase):
    def setUp(self):
        self.tracker = FineGrainedTaintTracker(calling_convention="amd64")

    def test_xor_zeroing_clears_taint(self):
        self.tracker.mark_tainted("rax", TaintTag.TAINTED_INPUT, "untrusted_socket")
        self.assertEqual(self.tracker.get_taint("rax")[0], TaintTag.TAINTED_INPUT)

        # xor eax, eax
        self.tracker.step_instruction("xor", ["eax", "eax"])
        self.assertEqual(self.tracker.get_taint("rax")[0], TaintTag.CLEAN)

    def test_taint_propagation_mov_and_arith(self):
        self.tracker.mark_tainted("rax", TaintTag.TAINTED_LENGTH, "packet_header")
        # mov rdx, rax
        self.tracker.step_instruction("mov", ["rdx", "rax"])
        self.assertEqual(self.tracker.get_taint("rdx")[0], TaintTag.TAINTED_LENGTH)

        # add rdx, 8
        self.tracker.step_instruction("add", ["rdx", "8"])
        self.assertEqual(self.tracker.get_taint("rdx")[0], TaintTag.TAINTED_LENGTH)

    def test_memcpy_length_taint_violation(self):
        # Setup: rdx holds tainted length from network input
        self.tracker.mark_tainted("rdx", TaintTag.TAINTED_LENGTH, "recv_buffer")
        # Call memcpy(rdi=dst, rsi=src, rdx=size)
        v = self.tracker.step_instruction("call", ["memcpy"])
        self.assertIsNotNone(v)
        self.assertEqual(v.sink_name, "memcpy")
        self.assertEqual(v.cwe_id, "CWE-119")
        self.assertEqual(v.violation_type, "TAINTED_LENGTH_ARGUMENT")
        self.assertEqual(v.tainted_operand, "rdx")

    def test_system_command_taint_violation(self):
        # Setup: rdi holds tainted command string
        self.tracker.mark_tainted("rdi", TaintTag.TAINTED_INPUT, "web_request")
        v = self.tracker.step_instruction("call", ["system"])
        self.assertIsNotNone(v)
        self.assertEqual(v.sink_name, "system")
        self.assertEqual(v.cwe_id, "CWE-78")
        self.assertEqual(v.violation_type, "TAINTED_COMMAND_EXECUTION")

    def test_indirect_call_taint_violation(self):
        self.tracker.mark_tainted("rax", TaintTag.TAINTED_POINTER, "heap_metadata")
        v = self.tracker.step_instruction("call", ["rax"])
        self.assertIsNotNone(v)
        self.assertEqual(v.cwe_id, "CWE-822")
        self.assertEqual(v.violation_type, "TAINTED_FUNCTION_POINTER_CALL")


class TestPhase24CFGBinDiff(unittest.TestCase):
    def setUp(self):
        self.differ = BinaryDiffEngine()

    def test_build_cfg_basic_blocks_and_complexity(self):
        instructions = [
            "push rbp",
            "mov rbp, rsp",
            "cmp rdi, 0",
            "je .L_error",
            "mov eax, 1",
            "jmp .L_exit",
            ".L_error:",
            "xor eax, eax",
            ".L_exit:",
            "pop rbp",
            "ret",
        ]
        cfg = self.differ.build_cfg_from_instructions(instructions, "sample_fn")
        self.assertGreaterEqual(len(cfg.basic_blocks), 3)
        self.assertGreaterEqual(cfg.cyclomatic_complexity, 2)
        self.assertIn("cmp", cfg.normalized_mnemonics)
        self.assertIn("je", cfg.normalized_mnemonics)

    def test_cfg_identical_function_similarity(self):
        instructions = [
            "mov eax, [rdi]",
            "add eax, 10",
            "ret",
        ]
        cfg1 = self.differ.build_cfg_from_instructions(instructions, "calc")
        cfg2 = self.differ.build_cfg_from_instructions(instructions, "calc")
        sim = self.differ.compute_cfg_similarity(cfg1, cfg2)
        self.assertEqual(sim, 1.0)

    def test_detect_security_hardening_guard(self):
        # Old vulnerable function without boundary validation
        old_fn = [
            "push rbp",
            "mov rbp, rsp",
            "call memcpy",
            "pop rbp",
            "ret",
        ]
        # New hardened function with cmp boundary guard
        new_fn = [
            "push rbp",
            "mov rbp, rsp",
            "cmp rdx, 256",
            "ja .L_err",
            "call memcpy",
            "jmp .L_done",
            ".L_err:",
            "mov eax, -1",
            ".L_done:",
            "pop rbp",
            "ret",
        ]
        diff_res = self.differ.diff_functions_cfg(
            old_functions={"process_packet": old_fn},
            new_functions={"process_packet": new_fn},
        )
        self.assertTrue(diff_res["security_hardening_detected"])
        self.assertEqual(len(diff_res["matches"]), 1)
        match = diff_res["matches"][0]
        self.assertEqual(match["name"], "process_packet")
        self.assertEqual(match["added_guards"], 1)
        self.assertIn("Hardened", match["description"])


if __name__ == "__main__":
    unittest.main()
