"""
Tests for Phase 3: 12-Stage Pipeline State Machine, Provenance & Scope Ledger, Dual Reporter.
"""

import os
import tempfile
import unittest

from reverse_forge.pipeline import AutonomyLevel, PipelineStateMachine, StageStatus
from reverse_forge.provenance import ProvenanceManager, ScopeLedger
from reverse_forge.reporter import Finding, ReportGenerator


class TestPhase3ProvenanceAndScope(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.prov_mgr = ProvenanceManager(self.tmp_dir.name)
        self.test_file = os.path.join(self.tmp_dir.name, "target_binary.bin")
        with open(self.test_file, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 128)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_scope_authorization(self):
        scope = ScopeLedger(allowed_patterns=["target_binary.bin"])
        self.assertTrue(scope.is_authorized("target_binary.bin"))
        self.assertFalse(scope.is_authorized("unauthorized_payload.exe"))

    def test_provenance_ingestion_and_immutability(self):
        prov = self.prov_mgr.ingest_artifact(self.test_file)
        self.assertEqual(prov.artifact_name, "target_binary.bin")
        self.assertTrue(os.path.exists(prov.working_copy_path))
        self.assertTrue(self.prov_mgr.verify_working_copy_integrity(prov))


class TestPhase3Reporter(unittest.TestCase):
    def test_dual_report_generation(self):
        rg = ReportGenerator(target_name="sample.exe", sha256="abcdef1234567890" * 4)
        rg.add_finding(Finding(
            finding_id="VULN-001",
            title="Insecure API strcpy in ParseInput",
            vulnerability_class="Buffer Overflow",
            confidence="Confirmed",
            cvss_score=8.5,
            cwe_id="CWE-120",
            function_symbol="ParseInput",
            address_or_offset="0x401050",
            what="Unbounded string copy",
            why="Missing size check",
            where="main.c:45",
            when="Processing HTTP header",
            how="Send buffer larger than 256 bytes",
            remediation="Replace with strncpy or safe string abstraction."
        ))

        json_out = rg.to_json()
        self.assertEqual(json_out["executive_summary"]["high_count"], 1)
        self.assertEqual(len(json_out["findings"]), 1)

        md_out = rg.to_markdown()
        self.assertIn("Insecure API strcpy in ParseInput", md_out)
        self.assertIn("**CVSS 4.0 Score:** `8.5`", md_out)


class TestPhase3PipelineStateMachine(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pe_file = os.path.join(self.tmp_dir.name, "sample.exe")
        # Write minimal valid PE stub
        with open(self.pe_file, "wb") as f:
            f.write(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_full_pipeline_execution(self):
        sm = PipelineStateMachine(
            artifact_path=self.pe_file,
            autonomy_level=AutonomyLevel.AUTONOMOUS,
            workspace_dir=self.tmp_dir.name
        )
        res = sm.run_all()
        self.assertIn("stages", res)
        self.assertEqual(len(res["stages"]), 12)
        # Stage 0 through 11 should have run
        for st in res["stages"]:
            self.assertIn(st["status"], (StageStatus.COMPLETED.value, StageStatus.SKIPPED.value))
        self.assertTrue(len(res["report_markdown"]) > 0)



    def test_full_pipeline_on_elf_binary(self):
        if os.path.exists("/bin/ls"):
            with open("/bin/ls", "rb") as f:
                header = f.read(4)
            if header == b"\x7fELF":
                sm = PipelineStateMachine(
                    artifact_path="/bin/ls",
                    autonomy_level=AutonomyLevel.AUTONOMOUS,
                    workspace_dir=self.tmp_dir.name
                )
                res = sm.run_all()
                for st in res["stages"]:
                    self.assertIn(st["status"], (StageStatus.COMPLETED.value, StageStatus.SKIPPED.value))
                self.assertGreaterEqual(len(res["report_json"]["findings"]), 1)


if __name__ == "__main__":
    unittest.main()
