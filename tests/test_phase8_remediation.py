"""
Tests for Phase 8: Defensive Remediation, Code Patches & Regression Harness Generation.
"""

import unittest

from reverse_forge.remediation_engine import RemediationEngine


class TestPhase8RemediationEngine(unittest.TestCase):
    def setUp(self):
        self.rem = RemediationEngine()

    def test_generate_cwe120_defensive_patch(self):
        patch = self.rem.generate_defensive_patch("VULN-001", "CWE-120", "ParseBuffer")
        self.assertEqual(patch.cwe_id, "CWE-120")
        self.assertIn("strncpy_s", patch.hardened_code_snippet)
        self.assertIn("--- vulnerable.c", patch.diff_patch)
        self.assertIn("/GS", patch.compiler_hardening_flags)

    def test_generate_cwe78_command_injection_patch(self):
        patch = self.rem.generate_defensive_patch("VULN-002", "CWE-78", "ExecuteScript")
        self.assertEqual(patch.cwe_id, "CWE-78")
        self.assertIn("execv", patch.hardened_code_snippet)
        self.assertIn("-fPIE", patch.compiler_hardening_flags)

    def test_generate_regression_test_harness(self):
        harness = self.rem.generate_regression_test_harness("sample_service", "CWE-120")
        self.assertEqual(harness.target_name, "sample_service")
        self.assertIn("assert(strlen(dest) < sizeof(dest))", harness.source_code)
        self.assertIn("gcc", harness.execution_command)


if __name__ == "__main__":
    unittest.main()
