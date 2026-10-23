"""
Tests for Phase 12: Stripped Function Signature & Wildcard Byte-Pattern Engine.
"""

import json
import os
import tempfile
import unittest

from reverse_forge.signature_engine import SignatureEngine


class TestPhase12SignatureEngine(unittest.TestCase):
    def setUp(self):
        self.engine = SignatureEngine()

    def test_wildcard_hex_pattern_matching(self):
        # Embed x86_64 CET ENDBR64 + frame setup + sub rsp, 0x20 + ChaCha20 constant
        blob = (
            b"\x90" * 16
            + bytes.fromhex("F3 0F 1E FA 55 48 89 E5 48 83 EC 20")
            + b"\x00" * 16
            + b"expand 32-byte k"
        )
        scan = self.engine.full_signature_scan(blob)
        rule_ids = [m["rule_id"] for m in scan["matches"]]
        self.assertIn("SIG-ARCH-X64-CET", rule_ids)
        self.assertIn("SIG-ARCH-X64-SYSV", rule_ids)
        self.assertIn("SIG-CRYPTO-CHACHA20", rule_ids)
        self.assertTrue(scan["stripped_function_recovery"]["has_cet_ibt"])
        self.assertGreaterEqual(scan["stripped_function_recovery"]["estimated_function_prologues_total"], 2)

    def test_arm64e_pac_prologue_detection(self):
        # ARM64e PACIASP (7F 23 03 D5) + STP X29, X30, [SP, #-0x10]! (FD 7B BF A9)
        blob = b"\x00" * 8 + bytes.fromhex("7F 23 03 D5 FD 7B BF A9") + b"\x00" * 8
        scan = self.engine.full_signature_scan(blob)
        rule_ids = [m["rule_id"] for m in scan["matches"]]
        self.assertIn("SIG-ARCH-ARM64E-PAC", rule_ids)
        self.assertTrue(scan["stripped_function_recovery"]["has_arm64_pac"])

    def test_custom_json_signature_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = os.path.join(tmpdir, "custom_sigs.json")
            custom_rules = [
                {
                    "rule_id": "CUSTOM-001",
                    "name": "custom_protocol_magic",
                    "category": "Protocol Marker",
                    "pattern_hex": "DE AD ?? EF",
                    "architecture": "any",
                    "description": "Custom protocol frame header",
                }
            ]
            with open(rules_file, "w", encoding="utf-8") as f:
                json.dump(custom_rules, f)

            added = self.engine.load_rules_from_json(rules_file)
            self.assertEqual(added, 1)
            matches = self.engine.scan_bytes(b"\x00\xde\xad\x42\xef\x00")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].rule_id, "CUSTOM-001")
            self.assertEqual(matches[0].offset, 1)


if __name__ == "__main__":
    unittest.main()
