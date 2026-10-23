"""
Tests for Phase 19 (Microcode IR AST Folding & Dead Store Elimination)
and Phase 20 (Bidirectional Cross-Function Struct Type Propagation).
"""

import unittest

from reverse_forge.microcode_optimizer import MicrocodeOptimizer
from reverse_forge.semantic_recovery import RecoveredFunctionSymbol, SemanticRecoveryEngine


class TestPhase19MicrocodeOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = MicrocodeOptimizer()

    def test_copy_propagation(self):
        lines = [
            "var_eax = arg1;",
            "var_ebx = var_eax;",
            "result = var_ebx + 5;"
        ]
        res = self.optimizer.copy_propagation(lines)
        self.assertIn("result = arg1 + 5;", res)

    def test_dead_store_elimination(self):
        lines = [
            "var_unused = 42;",
            "result = 100;",
            "return result;"
        ]
        res = self.optimizer.dead_store_elimination(lines)
        self.assertNotIn("var_unused = 42;", res)
        self.assertIn("return result;", res)

    def test_expression_folding(self):
        lines = [
            "*(int *)(ptr + 4) = 1;",
            "count = count + 1;",
            "val = *(buf + 0);"
        ]
        res = self.optimizer.expression_folding(lines)
        self.assertIn("ptr[1] = 1;", res)
        self.assertIn("count++;", res)
        self.assertIn("val = *buf;", res)


class TestPhase20BidirectionalTypePropagation(unittest.TestCase):
    def setUp(self):
        self.engine = SemanticRecoveryEngine()

    def test_cross_function_struct_propagation(self):
        # Function B accesses struct offsets +0x04 and +0x18
        callee_pseudocode = """
        int handle_packet(void *pkt) {
            uint32_t len = *(uint32_t *)(pkt + 0x04);
            char *buf = *(char **)(pkt + 0x18);
            return len;
        }
        """
        callee_meta = self.engine.recover_from_pseudocode("handle_packet", callee_pseudocode)
        self.assertEqual(len(callee_meta.recovered_struct_fields), 2)

        # Callgraph: main_worker calls handle_packet
        callgraph = {
            "main_worker": ["handle_packet"]
        }
        funcs_map = {
            "handle_packet": callee_meta
        }

        # Propagate types backward to caller
        propagated = self.engine.propagate_struct_types_across_callgraph(callgraph, funcs_map)
        self.assertIn("main_worker", propagated)
        worker_fields = propagated["main_worker"]
        self.assertEqual(len(worker_fields), 2)
        self.assertEqual(worker_fields[0]["offset"], "0x4")
        self.assertEqual(worker_fields[1]["offset"], "0x18")


if __name__ == "__main__":
    unittest.main()
