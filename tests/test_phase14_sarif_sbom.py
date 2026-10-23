"""
Tests for Phase 14: OASIS SARIF v2.1.0 & CycloneDX v1.5 Binary SBOM Exporter.
"""

import os
import tempfile
import unittest

from reverse_forge.pipeline import AutonomyLevel, PipelineStateMachine
from reverse_forge.sarif_sbom_exporter import CycloneDXExporter, SARIFExporter


class TestPhase14SARIFAndSBOM(unittest.TestCase):
    def test_sarif_v2_1_0_schema_and_severity_mapping(self):
        fake_state = {
            "artifact": "service.elf",
            "sha256": "abcd1234" * 8,
            "report_json": {
                "findings": [
                    {
                        "finding_id": "ELF-VULN-05",
                        "title": "Use of Banned Unbounded Memory/String Functions",
                        "cvss_score": 7.8,
                        "cwe_id": "CWE-120",
                        "function_symbol": "parse_packet",
                        "address_or_offset": "0x401200",
                        "what": "Imports strcpy",
                        "why": "Unbounded copy",
                        "remediation": "Use strncpy_s",
                    }
                ]
            },
        }
        sarif = SARIFExporter.to_sarif(fake_state)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "R3V3R53//F0RG3")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "7.8")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["results"][0]["ruleId"], "ELF-VULN-05")

    def test_cyclonedx_v1_5_sbom_generation(self):
        fake_state = {
            "artifact": "service.elf",
            "sha256": "abcd1234" * 8,
            "report_json": {
                "findings": [
                    {
                        "finding_id": "ELF-VULN-05",
                        "title": "Unbounded copy",
                        "cvss_score": 7.8,
                        "cwe_id": "CWE-120",
                        "what": "strcpy used",
                        "remediation": "Use bounds check",
                    }
                ]
            },
        }
        static_meta = {
            "shared_libraries": ["libc.so.6", "libssl.so.3"],
            "signature_scan": {
                "matches": [
                    {"name": "chacha20_constant_expand_32_byte_k", "category": "Cryptographic Constant"}
                ]
            },
        }
        cdx = CycloneDXExporter.to_cyclonedx(fake_state, static_metadata=static_meta)
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.5")
        comp_names = [c["name"] for c in cdx["components"]]
        self.assertIn("libc.so.6", comp_names)
        self.assertIn("libssl.so.3", comp_names)
        self.assertIn("chacha20_constant_expand_32_byte_k", comp_names)
        self.assertEqual(len(cdx["vulnerabilities"]), 1)
        self.assertEqual(cdx["vulnerabilities"][0]["cwes"], [120])

    def test_end_to_end_pipeline_sarif_and_sbom_on_ls(self):
        if os.path.exists("/bin/ls"):
            with open("/bin/ls", "rb") as f:
                header = f.read(4)
            if header == b"\x7fELF":
                with tempfile.TemporaryDirectory() as tmpdir:
                    sm = PipelineStateMachine("/bin/ls", autonomy_level=AutonomyLevel.AUTONOMOUS, workspace_dir=tmpdir)
                    state = sm.run_all()
                    sarif = SARIFExporter.to_sarif(state)
                    cdx = CycloneDXExporter.to_cyclonedx(state, static_metadata=sm.static_metadata)
                    self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)
                    self.assertGreaterEqual(len(cdx["components"]), 1)


if __name__ == "__main__":
    unittest.main()
