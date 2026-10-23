"""
Tests for Phase 27 & Phase 28: Zero-Day Heuristic Cluster Engine & Patch Verification Harness.
"""

import unittest
from reverse_forge.zeroday_cluster_engine import ZeroDayClusterEngine, ZeroDayCandidate
from reverse_forge.remediation_engine import RemediationEngine
from reverse_forge.patch_verifier import PatchVerifier, PatchVerificationReport


class TestPhase27ZeroDayClusterEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ZeroDayClusterEngine(anomaly_threshold=0.60)

    def test_detect_unguarded_memory_writer(self):
        # Vulnerable zero-day candidate: reading from network and writing directly to buffer without checks
        bad_func = [
            "push rbp",
            "mov rbp, rsp",
            "call recv",
            "mov [rdi], al",
            "mov [rdi+1], bl",
            "mov [rdi+2], cl",
            "mov [rdi+3], dl",
            "pop rbp",
            "ret",
        ]
        candidates = self.engine.analyze_functions(
            functions_dict={"vuln_network_unpacker": bad_func},
            call_graph={"vuln_network_unpacker": {"recv"}},
        )
        self.assertEqual(len(candidates), 1)
        cand = candidates[0]
        self.assertEqual(cand.function_name, "vuln_network_unpacker")
        self.assertGreaterEqual(cand.anomaly_score, 0.65)
        self.assertEqual(cand.cluster_category, "UNGUARDED_MEMORY_WRITER")
        self.assertGreaterEqual(cand.estimated_cvss, 7.5)

    def test_normal_function_low_anomaly(self):
        # Clean guarded function
        safe_func = [
            "push rbp",
            "mov rbp, rsp",
            "cmp rdi, 256",
            "ja .L_err",
            "mov eax, 1",
            "jmp .L_done",
            ".L_err:",
            "xor eax, eax",
            ".L_done:",
            "pop rbp",
            "ret",
        ]
        candidates = self.engine.analyze_functions(
            functions_dict={"safe_math": safe_func},
            call_graph={"safe_math": set()},
        )
        self.assertEqual(len(candidates), 0)


class TestPhase28PatchVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = PatchVerifier()
        self.rem_engine = RemediationEngine()

    def test_verify_defensive_patch_resilience_cwe120(self):
        patch = self.rem_engine.generate_defensive_patch("FIND-01", "CWE-120", "process_packet")
        report = self.verifier.verify_patch_resilience(patch, buffer_capacity=256)
        self.assertEqual(report.verdict, "VERIFIED_DEFENDED")
        self.assertTrue(report.exploit_payload_blocked)
        self.assertTrue(report.benign_input_accepted)
        self.assertIn("strncpy_s", report.verification_harness_c)
        self.assertIn("class TestPatchResilience", report.verification_harness_py)

    def test_verify_defensive_patch_cwe78(self):
        patch = self.rem_engine.generate_defensive_patch("FIND-02", "CWE-78", "spawn_worker")
        report = self.verifier.verify_patch_resilience(patch, buffer_capacity=512)
        self.assertEqual(report.verdict, "VERIFIED_DEFENDED")
        self.assertIn("execv", report.verification_harness_c)


if __name__ == "__main__":
    unittest.main()
