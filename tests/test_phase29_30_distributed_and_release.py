"""
Tests for Phase 29 & Phase 30: Distributed Corpus Clustering & Release Automation.
"""

import os
import struct
import tempfile
import unittest

from reverse_forge.distributed_corpus import DistributedCorpusClusteringEngine, CorpusClusterReport


class TestPhase29DistributedCorpus(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        
        # Create synthetic ELF
        elf_path = os.path.join(self.tmp_dir.name, "worker1.elf")
        with open(elf_path, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 0, 0, 0, 64, 56, 1, 64, 0, 0) + b"\x00" * 256)

        # Create synthetic PE
        pe_path = os.path.join(self.tmp_dir.name, "worker2.exe")
        with open(pe_path, "wb") as f:
            f.write(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200)

        self.engine = DistributedCorpusClusteringEngine(max_workers=2)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_scan_and_cluster_directory(self):
        report = self.engine.scan_and_cluster_directory(self.tmp_dir.name, recursive=False)
        self.assertGreaterEqual(report.total_artifacts, 2)
        self.assertGreaterEqual(report.total_families, 1)
        self.assertEqual(report.concurrency_workers, 2)
        self.assertGreater(report.processing_time_sec, 0.0)

        fmts = [fam.architecture_format for fam in report.families]
        self.assertTrue("ELF" in fmts or "PE" in fmts)


class TestPhase30ReleaseWorkflowIntegrity(unittest.TestCase):
    def test_release_workflow_exists_and_structured(self):
        wf_path = os.path.join(".github", "workflows", "release_and_benchmark.yml")
        self.assertTrue(os.path.exists(wf_path))
        with open(wf_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("R3V3R53//F0RG3 Release & Autonomous Benchmark Workflow", content)
        self.assertIn("ubuntu-latest", content)
        self.assertIn("windows-latest", content)
        self.assertIn("macos-latest", content)
        self.assertIn("unittest discover", content)


if __name__ == "__main__":
    unittest.main()
