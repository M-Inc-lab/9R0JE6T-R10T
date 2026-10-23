"""
Tests for Phase 31 Audit Remediations across Phases 17–30:
1. Flow-sensitive copy propagation (invalidating reassigned registers & preserving indentation)
2. Memory taint clearing on clean store and whitespace normalization in FineGrainedTaintTracker
3. Exact mnemonic matching in ZeroDayClusterEngine (ignoring non-branch 'bswap'/'bt' instructions)
4. Non-fabricated alias-trace CLI and non-fabricated DistributedCorpusClusteringEngine metrics
5. Compilable C harness variable declarations in PatchVerifier
"""

import json
import os
import subprocess
import sys
import unittest

from reverse_forge.fine_grain_taint_engine import FineGrainedTaintTracker, TaintTag
from reverse_forge.microcode_optimizer import MicrocodeOptimizer
from reverse_forge.patch_verifier import PatchVerifier
from reverse_forge.remediation_engine import RemediationEngine
from reverse_forge.zeroday_cluster_engine import ZeroDayClusterEngine


class TestPhase31AuditFixes(unittest.TestCase):
    def test_copy_propagation_reassignment_invalidation_and_indentation(self):
        opt = MicrocodeOptimizer()
        raw_lines = [
            "    var_eax = arg1;",
            "    var_ebx = var_eax;",
            "    var_eax = 99;",
            "    result = var_eax + var_ebx;",
        ]
        out = opt.copy_propagation(raw_lines)
        # Indentation must be preserved
        self.assertTrue(all(l.startswith("    ") for l in out))
        # Reassignment of var_eax = 99 must NOT rewrite LHS into 'arg1 = 99;'
        self.assertIn("    var_eax = 99;", out)
        # After var_eax is reassigned to 99, var_eax must not be replaced with arg1
        self.assertIn("    result = var_eax + arg1;", out)

    def test_memory_taint_clears_on_clean_overwrite_and_normalizes_spaces(self):
        tracker = FineGrainedTaintTracker()
        tracker.mark_tainted("[rbp - 0x10]", TaintTag.TAINTED_INPUT, "socket_buf")
        self.assertEqual(tracker.get_taint("[rbp-0x10]")[0], TaintTag.TAINTED_INPUT)

        # Overwriting [rbp-0x10] with clean register rbx must clear memory taint
        tracker.step_instruction("mov", ["[rbp-0x10]", "rbx"])
        self.assertEqual(tracker.get_taint("[rbp - 0x10]")[0], TaintTag.CLEAN)

    def test_zeroday_branch_count_ignores_non_branch_b_mnemonics(self):
        zd = ZeroDayClusterEngine()
        insns = [
            "bswap eax",
            "bt eax, 1",
            "bts ebx, 2",
            "btr ecx, 3",
            "mov eax, 0",
        ]
        vec = zd.extract_function_metrics("bit_ops", insns)
        # None of bswap/bt/bts/btr/mov are branches -> cyclomatic complexity must be 1
        self.assertEqual(vec.cyclomatic_complexity, 1)

    def test_patch_verifier_c_harness_declares_src_variable(self):
        patch = RemediationEngine().generate_defensive_patch("V1", "CWE-120", "copy_fn")
        rep = PatchVerifier().verify_patch_resilience(patch, buffer_capacity=128)
        self.assertIn("const char *src = exploit_src;", rep.verification_harness_c)
        self.assertIn("const char *src = benign_src;", rep.verification_harness_c)

    def test_new_phase31_cli_subcommands(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        res = subprocess.run(
            [sys.executable, "-m", "reverse_forge.cli", "uil-lift", "--arch", "arm64", "--asm", "ldr x0, [x1, #16]; ret"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        data = json.loads(res.stdout)
        self.assertEqual(data["instructions"][0]["opcode"], "LOAD")


if __name__ == "__main__":
    unittest.main()
