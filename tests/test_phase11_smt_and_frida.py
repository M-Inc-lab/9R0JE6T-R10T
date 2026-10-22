"""
Tests for Phase 11: SMT Path Feasibility & Guard Completeness Solver and Frida DBI Script Synthesizer.
"""

import os
import tempfile
import unittest

from reverse_forge.frida_dbi_engine import FridaDBIEngine
from reverse_forge.smt_solver_engine import PathConstraint, SMTSolverEngine


class TestPhase11SMTAndFrida(unittest.TestCase):
    def setUp(self):
        self.solver = SMTSolverEngine()

    def test_smt_sat_and_unsat_paths(self):
        # 1. Satisfiable path: x > 10, x < 20, x % 4 == 0 -> x in {12, 16}
        sat_constraints = [
            PathConstraint(var="x", op="GT", value=10),
            PathConstraint(var="x", op="LT", value=20),
            PathConstraint(var="x", op="MOD_EQ", value=0, modulus_or_mask=4),
        ]
        res = self.solver.solve_constraints(sat_constraints)
        self.assertTrue(res.is_feasible)
        self.assertEqual(res.status, "SAT")
        self.assertIn(res.model["x"], (12, 16))

        # 2. Unsatisfiable path (dead code): x >= 100 and x <= 50
        unsat_constraints = [
            PathConstraint(var="x", op="GE", value=100),
            PathConstraint(var="x", op="LE", value=50),
        ]
        res_unsat = self.solver.solve_constraints(unsat_constraints)
        self.assertFalse(res_unsat.is_feasible)
        self.assertEqual(res_unsat.status, "UNSAT")

    def test_smt_guard_completeness_verification(self):
        # Incomplete guard: len >= 0 and len <= 128 on a 64-byte buffer -> INCOMPLETE_GUARD (CWE-787)
        weak_guard = [
            PathConstraint(var="len", op="GE", value=0),
            PathConstraint(var="len", op="LE", value=128),
        ]
        check_weak = self.solver.verify_guard_completeness(weak_guard, "len", buffer_capacity=64)
        self.assertEqual(check_weak["guard_status"], "INCOMPLETE_GUARD")
        self.assertEqual(check_weak["cwe_id"], "CWE-787")
        self.assertGreater(check_weak["counterexample"]["len"], 64)

        # Complete guard: len >= 0 and len <= 64 on a 64-byte buffer -> GUARD_COMPLETE
        strong_guard = [
            PathConstraint(var="len", op="GE", value=0),
            PathConstraint(var="len", op="LE", value=64),
        ]
        check_strong = self.solver.verify_guard_completeness(strong_guard, "len", buffer_capacity=64)
        self.assertEqual(check_strong["guard_status"], "GUARD_COMPLETE")
        self.assertIsNone(check_strong["cwe_id"])

    def test_frida_dbi_script_generation_and_sanitization(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            js_path = os.path.join(tmpdir, "hooks.js")
            out = FridaDBIEngine.write_frida_script(js_path, ["recv", "strcpy", "0x401000"], module_name="libc.so.6")
            self.assertTrue(os.path.exists(out))
            with open(out, "r", encoding="utf-8") as f:
                js_content = f.read()
            self.assertIn("Interceptor.attach", js_content)
            self.assertIn('"libc.so.6"', js_content)
            self.assertIn('"recv"', js_content)

        # Reject injection characters in symbol names
        with self.assertRaises(ValueError):
            FridaDBIEngine.generate_frida_trace_script(["invalid;symbol"])


if __name__ == "__main__":
    unittest.main()
