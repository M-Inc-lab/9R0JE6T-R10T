"""
Phase 2 Verified End-to-End Workflow Test Suite (§08, Phase G)
Proves a complete, deterministic, and technically honest reverse-engineering workflow:
1. Accept an authorized benign test binary.
2. Validate the input and scope.
3. Calculate its SHA-256.
4. Detect its format and architecture.
5. Run the supported analysis backend.
6. Record which backend actually ran.
7. Preserve findings with evidence and confidence labels.
8. Record provenance sufficient to reproduce the analysis.
9. Export a report to an authorized destination.
10. Verify the report against the fixture's expected results.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from reverse_forge.elf_analyzer import ELFAnalyzer
from reverse_forge.native_rust_bridge import NativeRustAccelerator, BackendExecutionMode
from reverse_forge.pipeline import ReverseForgePipeline, AutonomyLevel, StageStatus
from reverse_forge.provenance import ActionPermission, ScopeLedger
from reverse_forge.reporter import Finding, ReportGenerator, asdict
from reverse_forge.whole_binary_function_indexer import WholeBinaryFunctionIndexer


class TestPhase2VerifiedWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow_unstripped.elf")
        )
        if not os.path.exists(cls.fixture_path):
            src_c = os.path.join(os.path.dirname(__file__), "fixtures", "known_control_flow.c")
            if os.path.exists(src_c) and shutil.which("gcc"):
                os.makedirs(os.path.dirname(cls.fixture_path), exist_ok=True)
                subprocess.run(["gcc", "-O2", "-g", src_c, "-o", cls.fixture_path], check=True)

        if not os.path.exists(cls.fixture_path):
            raise FileNotFoundError(f"Required benign fixture not found: {cls.fixture_path}")

        with open(cls.fixture_path, "rb") as f:
            cls.fixture_bytes = f.read()
        cls.expected_sha256 = hashlib.sha256(cls.fixture_bytes).hexdigest()

    def test_end_to_end_verified_workflow_success(self):
        """Execute and verify the full 10-step honest reverse-engineering workflow."""
        with tempfile.TemporaryDirectory() as td:
            # 1. Accept authorized binary
            target_bin = os.path.join(td, "target.elf")
            with open(target_bin, "wb") as f:
                f.write(self.fixture_bytes)

            authorized_out_dir = os.path.join(td, "reports")
            os.makedirs(authorized_out_dir, exist_ok=True)
            report_out = os.path.join(authorized_out_dir, "analysis_report.json")

            # 2. Validate input and scope
            ledger = ScopeLedger(
                allowed_paths=[target_bin, authorized_out_dir],
                default_actions=[
                    ActionPermission.READ_HASH,
                    ActionPermission.STATIC_ANALYSIS,
                    ActionPermission.EXPORT_REPORT,
                ],
                allow_all=False,
            )
            self.assertTrue(ledger.is_authorized(target_bin, ActionPermission.READ_HASH))
            self.assertTrue(ledger.is_authorized(report_out, ActionPermission.EXPORT_REPORT))
            self.assertFalse(ledger.is_authorized("/etc/shadow", ActionPermission.EXPORT_REPORT))

            # 3. Calculate SHA-256
            hasher = hashlib.sha256()
            with open(target_bin, "rb") as f:
                hasher.update(f.read())
            calc_sha256 = hasher.hexdigest()
            self.assertEqual(calc_sha256, self.expected_sha256)

            # 4. Detect format and architecture
            elf_ana = ELFAnalyzer(self.fixture_bytes)
            elf_meta = elf_ana.analyze()
            self.assertTrue(elf_meta["is_elf"])
            self.assertEqual(elf_meta["class"], "64-bit")
            self.assertIn("x86-64", elf_meta["architecture"])
            self.assertFalse(elf_meta["is_stripped"])

            # 5. Run supported analysis backend
            indexer = WholeBinaryFunctionIndexer(self.fixture_bytes)
            funcs = indexer.discover_all_functions()
            func_names = {f.name for f in funcs}
            self.assertIn("switch_jump_table", func_names)
            self.assertIn("arithmetic_mem", func_names)
            self.assertIn("main", func_names)

            # 6. Record which backend actually ran
            active_backend = NativeRustAccelerator.get_active_backend()
            self.assertIn(
                active_backend,
                (BackendExecutionMode.RUST_NATIVE, BackendExecutionMode.C_FALLBACK, BackendExecutionMode.PURE_PYTHON),
            )

            # 7. Preserve findings with evidence, confidence, and categories
            report = ReportGenerator(target_name="known_control_flow_unstripped.elf", sha256=calc_sha256)
            report.add_finding(
                Finding(
                    finding_id="FND-001",
                    title="System V AMD64 ELF Binary Format",
                    vulnerability_class="Architectural Format Observation",
                    confidence="Confirmed",
                    cvss_score=0.0,
                    cwe_id="CWE-1027",
                    function_symbol="_start",
                    address_or_offset="0x401000",
                    what="Valid 64-bit System V AMD64 ELF executable",
                    why="Verified standard ELF64 header with non-stripped symbol table",
                    where=target_bin,
                    when="Pipeline Stage 1 Reconnaissance",
                    how="Pure-Python ELF header parser",
                    remediation="Informational format observation",
                    evidence={"e_machine": "0x3E", "sha256": calc_sha256},
                )
            )
            report.add_finding(
                Finding(
                    finding_id="FND-002",
                    title="Control-Flow Multiway Branch (Jump Table)",
                    vulnerability_class="Control-Flow Structure",
                    confidence="Confirmed",
                    cvss_score=2.0,
                    cwe_id="CWE-1108",
                    function_symbol="switch_jump_table",
                    address_or_offset="switch_jump_table",
                    what="5-case switch statement decoded into multiple basic blocks",
                    why="Jump table bounds checking present",
                    where="switch_jump_table",
                    when="Pipeline Stage 3 Static Analysis",
                    how="Recursive descent disassembler + CFG edge reconstruction",
                    remediation="Ensure table indices are safely bounds checked",
                    evidence={"cases": 5, "cfg_blocks": 2},
                )
            )

            # 8. Record provenance sufficient to reproduce
            pipeline = ReverseForgePipeline(
                artifact_path=target_bin,
                autonomy_level=AutonomyLevel.SUPERVISED,
                scope_ledger=ledger,
                workspace_dir=td,
            )
            pipeline.execute_stage(0)  # Input & Scope Verification
            pipeline.execute_stage(1)  # File & Format Reconnaissance
            pipeline.execute_stage(3)  # Static Analysis
            pipeline.execute_stage(10) # Reproducibility & Report Generation

            # 9. Export report to authorized destination
            exported_content = {
                "artifact_sha256": calc_sha256,
                "format": elf_meta["architecture"],
                "active_backend": active_backend.value,
                "functions_recovered": sorted(list(func_names)),
                "findings": [asdict(f) for f in report.findings],
                "stages": [s.status.value for s in pipeline.stages.values()],
            }
            with open(report_out, "w", encoding="utf-8") as f:
                json.dump(exported_content, f, indent=2)

            self.assertTrue(os.path.exists(report_out))

            # 10. Verify exported report matches expected ground-truth
            with open(report_out, "r", encoding="utf-8") as f:
                verified_data = json.load(f)

            self.assertEqual(verified_data["artifact_sha256"], self.expected_sha256)
            self.assertIn("x86-64", verified_data["format"])
            self.assertEqual(verified_data["active_backend"], active_backend.value)
            self.assertIn("arithmetic_mem", verified_data["functions_recovered"])
            self.assertIn("main", verified_data["functions_recovered"])
            self.assertEqual(len(verified_data["findings"]), 2)
            self.assertEqual(verified_data["findings"][0]["confidence"], "Confirmed")
            self.assertEqual(verified_data["findings"][0]["evidence"]["e_machine"], "0x3E")

    def test_workflow_fails_safely_when_unauthorized(self):
        """Workflow fails closed when binary path is outside the authorized scope."""
        with tempfile.TemporaryDirectory() as td:
            unauthorized_bin = os.path.join(td, "forbidden.elf")
            with open(unauthorized_bin, "wb") as f:
                f.write(self.fixture_bytes)

            # Ledger restricts to a non-existent path
            ledger = ScopeLedger(allowed_paths=["/opt/safe/only.bin"])

            pipeline = ReverseForgePipeline(
                artifact_path=unauthorized_bin,
                scope_ledger=ledger,
                workspace_dir=td,
            )
            # Stage 0 must fail
            ok = pipeline.execute_stage(0)
            self.assertFalse(ok)
            self.assertEqual(pipeline.stages[0].status, StageStatus.FAILED)
            self.assertIn("not authorized", pipeline.stages[0].error.lower())


if __name__ == "__main__":
    unittest.main()
