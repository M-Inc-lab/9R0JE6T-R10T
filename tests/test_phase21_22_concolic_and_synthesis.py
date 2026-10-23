"""
Tests for Phase 21 & Phase 22: Concolic Path Pruner and Exploit Synthesizer.
"""

import unittest
from reverse_forge.smt_solver_engine import PathConstraint, SMTSolverEngine
from reverse_forge.concolic_engine import ConcolicPathPruner, ExploitSynthesisResult


class TestPhase21ConcolicPathPruning(unittest.TestCase):
    def setUp(self):
        self.pruner = ConcolicPathPruner()

    def test_prune_infeasible_branch(self):
        # Branch 1: x > 100
        # Branch 2: x < 50
        history = [PathConstraint(var="x", op="GT", value=100)]
        candidate = PathConstraint(var="x", op="LT", value=50)
        feasible, model = self.pruner.evaluate_branch_feasibility(history, candidate)
        self.assertFalse(feasible)
        self.assertIsNone(model)

    def test_admit_feasible_branch(self):
        history = [PathConstraint(var="x", op="GT", value=100)]
        candidate = PathConstraint(var="x", op="LT", value=200)
        feasible, model = self.pruner.evaluate_branch_feasibility(history, candidate)
        self.assertTrue(feasible)
        self.assertIsNotNone(model)
        self.assertGreater(model["x"], 100)
        self.assertLess(model["x"], 200)


class TestPhase22SATExploitSynthesis(unittest.TestCase):
    def setUp(self):
        self.pruner = ConcolicPathPruner()

    def test_synthesize_buffer_overflow_payload(self):
        # Path condition: user_len < 1024, but buffer is only 256 bytes
        constraints = [
            PathConstraint(var="user_len", op="GT", value=0),
            PathConstraint(var="user_len", op="LT", value=1024),
        ]
        result = self.pruner.synthesize_exploit_trigger(
            path_constraints=constraints,
            length_var="user_len",
            buffer_capacity=256,
            sink_name="memcpy",
        )
        self.assertTrue(result.is_satisfiable)
        self.assertEqual(result.cwe_classification, "CWE-787: Out-of-bounds Write")
        self.assertGreater(result.payload_input["user_len"], 256)

    def test_synthesize_safe_bounded_guard(self):
        # Strict boundary guard: user_len <= 128, buffer is 256
        constraints = [
            PathConstraint(var="user_len", op="GE", value=0),
            PathConstraint(var="user_len", op="LE", value=128),
        ]
        result = self.pruner.synthesize_exploit_trigger(
            path_constraints=constraints,
            length_var="user_len",
            buffer_capacity=256,
            sink_name="strcpy",
        )
        self.assertFalse(result.is_satisfiable)
        self.assertEqual(result.cwe_classification, "SAFE_PATH")


if __name__ == "__main__":
    unittest.main()
