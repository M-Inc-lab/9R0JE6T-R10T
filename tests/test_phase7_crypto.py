"""
Tests for Phase 7: Cryptographic Primitive & Hardcoded Secret Discovery.
"""

import unittest

from reverse_forge.crypto_engine import CryptoSecretEngine


class TestPhase7CryptoSecretEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CryptoSecretEngine()

    def test_detect_md5_constant_table(self):
        # Embed MD5 IV constants
        blob = b"\x90" * 32 + bytes.fromhex("0123456789abcdeffedcba9876543210") + b"\x90" * 32
        matches = self.engine.scan_crypto_primitives(blob)
        names = [m.primitive_name for m in matches]
        self.assertIn("MD5_IV", names)

    def test_detect_hardcoded_aws_and_jwt_secrets(self):
        sample_payload = (
            b"data_chunk\x00"
            b"aws_key = AKIAIOSFODNN7EXAMPLE\x00"
            b"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            b"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            b"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\x00"
        )
        secrets = self.engine.scan_hardcoded_secrets(sample_payload)
        types = [s.secret_type for s in secrets]
        self.assertIn("AWS_ACCESS_KEY", types)
        self.assertIn("JWT_BEARER_TOKEN", types)

    def test_full_crypto_audit(self):
        blob = b"AKIA1111111111111111" + bytes.fromhex("0123456789abcdeffedcba9876543210")
        audit = self.engine.full_crypto_audit(blob)
        self.assertEqual(audit["crypto_hygiene_status"], "VULNERABLE")
        self.assertGreaterEqual(audit["high_risk_secrets_count"], 1)
        self.assertGreaterEqual(audit["weak_algorithms_count"], 1)


if __name__ == "__main__":
    unittest.main()
