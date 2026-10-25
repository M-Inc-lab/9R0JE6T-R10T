"""
Tests for Phase 15: Batch Directory Corpus Scanner & SQLite Artifact Knowledge Base.
"""

import os
import struct
import tempfile
import unittest

from reverse_forge.corpus_db import ArtifactKnowledgeBase, BatchCorpusScanner


class TestPhase15CorpusAndKnowledgeBase(unittest.TestCase):
    def test_batch_corpus_scan_and_sqlite_indexing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            corpus_dir = os.path.join(tmpdir, "firmware_rootfs")
            os.makedirs(corpus_dir, exist_ok=True)
            db_path = os.path.join(tmpdir, "test_kb.sqlite")
            ws_dir = os.path.join(tmpdir, "ws")

            # 1. Write synthetic PE binary
            pe_path = os.path.join(corpus_dir, "agent.exe")
            with open(pe_path, "wb") as f:
                f.write(b"MZ" + b"\x00" * 62 + b"PE\x00\x00" + b"\x00" * 200)

            # 2. Write synthetic ELF64 binary (non-PIE ET_EXEC without NX)
            elf_path = os.path.join(corpus_dir, "daemon.elf")
            elf_hdr = (
                b"\x7fELF\x02\x01\x01" + b"\x00" * 9
                + struct.pack("<HHIQQQIHHHHHH", 2, 0x3E, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
            )
            with open(elf_path, "wb") as f:
                f.write(elf_hdr)

            # 3. Write non-binary text file (should be skipped automatically)
            with open(os.path.join(corpus_dir, "readme.txt"), "w", encoding="utf-8") as f:
                f.write("plain text file")

            kb = ArtifactKnowledgeBase(db_path)
            scanner = BatchCorpusScanner(kb=kb, workspace_dir=ws_dir)
            rollup = scanner.scan_directory(corpus_dir)

            self.assertEqual(rollup["last_batch_scanned_count"], 2)
            self.assertEqual(rollup["last_batch_skipped_non_binary"], 1)
            self.assertEqual(rollup["total_indexed_artifacts"], 2)
            self.assertEqual(rollup["format_breakdown"]["PE"], 1)
            self.assertEqual(rollup["format_breakdown"]["ELF"], 1)

            # Query findings by CWE-119
            cwe119_hits = kb.query_findings(cwe_id="CWE-119", min_cvss=5.0)
            self.assertGreaterEqual(len(cwe119_hits), 1)

    def test_idempotent_upsert_on_same_sha256(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "upsert.sqlite")
            kb = ArtifactKnowledgeBase(db_path)
            fake_state = {
                "artifact": "sample.bin",
                "sha256": "11223344" * 8,
                "report_json": {
                    "executive_summary": {"overall_posture": "HIGH RISK", "total_findings": 1, "high_count": 1},
                    "findings": [
                        {
                            "finding_id": "ELF-VULN-01",
                            "title": "Missing NX",
                            "cwe_id": "CWE-119",
                            "cvss_score": 7.8,
                            "confidence": "Confirmed",
                            "function_symbol": "PT_GNU_STACK",
                            "address_or_offset": "0x0",
                        }
                    ],
                },
            }
            kb.store_pipeline_result(fake_state, "/tmp/sample.bin", "ELF", 1024)
            kb.store_pipeline_result(fake_state, "/tmp/sample.bin", "ELF", 1024)

            summary = kb.get_corpus_summary()
            self.assertEqual(summary["total_indexed_artifacts"], 1)
            self.assertEqual(len(kb.query_findings()), 1)

    def test_context_manager_and_clean_connection(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "ctx_test.sqlite")
            with ArtifactKnowledgeBase(db_path) as kb:
                conn = kb._connect()
                self.assertIsInstance(conn, sqlite3.Connection)
                summary = kb.get_corpus_summary()
                self.assertEqual(summary["total_indexed_artifacts"], 0)

            # Explicit close test
            kb2 = ArtifactKnowledgeBase(db_path)
            conn2 = kb2._connect()
            self.assertIsInstance(conn2, sqlite3.Connection)
            kb2.close()

            # Scanner context manager
            with BatchCorpusScanner(kb=ArtifactKnowledgeBase(db_path)) as scanner:
                self.assertIsNotNone(scanner.kb)


if __name__ == "__main__":
    unittest.main()

