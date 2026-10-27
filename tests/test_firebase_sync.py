"""
Unit & Integration Tests for Firebase Cloud Sync Module (Dimension 2: Backend Architecture & Firebase)
Updated for Stage 2 & Stage 4: Cryptographic JWT verification, fail-closed auth, and tenant isolation.
"""

import os
import time
import unittest
from unittest.mock import patch

try:
    import jwt
except ImportError:
    jwt = None

from reverse_forge.firebase_sync import (
    AuthUserContext,
    FirebaseAuthManager,
    FirebaseSyncManager,
    LocalSimulationPersistenceAdapter,
    UserRole,
)


class TestFirebaseSyncEngine(unittest.TestCase):
    def setUp(self):
        self.sync = FirebaseSyncManager(project_id="test-reverse-forge", force_local_sim=True)
        self.auth = self.sync.auth
        self.test_secret = "test-secret-key-32-bytes-minimum-length-for-hmac-sha256"
        self.auth.verification_key = self.test_secret
        self.auth.allowed_algorithms = ["HS256"]

    def test_mock_auth_fallback_in_dev_mode(self):
        """In development mode, mock auth provides developer context."""
        user = self.auth.verify_bearer_token(None)
        self.assertIsNotNone(user)
        self.assertEqual(user.role, UserRole.LEAD_ARCHITECT)
        self.assertTrue(user.can_modify())
        self.assertTrue(user.is_lead())

    def test_bearer_jwt_cryptographic_verification_and_rbac(self):
        """Verify signed JWT with valid claims is decoded and verified cryptographically."""
        payload = {
            "sub": "user_123",
            "email": "analyst@lab.org",
            "role": "ANALYST",
            "tenant_id": "lab_a",
            "exp": time.time() + 3600,
            "aud": "test-reverse-forge",
        }
        signed_jwt = jwt.encode(payload, self.test_secret, algorithm="HS256")

        user = self.auth.verify_bearer_token(f"Bearer {signed_jwt}")
        self.assertIsNotNone(user)
        self.assertEqual(user.uid, "user_123")
        self.assertEqual(user.email, "analyst@lab.org")
        self.assertEqual(user.role, UserRole.ANALYST)
        self.assertEqual(user.tenant_id, "lab_a")
        self.assertTrue(user.can_modify())
        self.assertFalse(user.is_lead())
        self.assertTrue(user.is_verified)

    def test_unsigned_jwt_strictly_rejected(self):
        """Security regression: tokens with alg='none' or unsigned payloads must be rejected."""
        fake_jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJoYWNrZXIifQ."
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {fake_jwt}"))

    def test_tampered_jwt_signature_rejected(self):
        """Tokens with tampered signatures must fail cryptographic verification."""
        payload = {
            "sub": "user_tampered",
            "exp": time.time() + 3600,
            "aud": "test-reverse-forge",
        }
        valid_jwt = jwt.encode(payload, self.test_secret, algorithm="HS256")
        tampered_jwt = valid_jwt[:-4] + "AAAA"
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {tampered_jwt}"))

    def test_production_mode_rejects_missing_auth_header(self):
        """In production, missing authorization headers fail closed (return None)."""
        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "production"}):
            prod_auth = FirebaseAuthManager(project_id="prod-project")
            self.assertIsNone(prod_auth.verify_bearer_token(None))
            self.assertIsNone(prod_auth.verify_bearer_token(""))

    def test_viewer_role_cannot_modify_findings(self):
        viewer = AuthUserContext(uid="view_1", email="view@lab.org", role=UserRole.VIEWER, tenant_id="tenant_x")
        self.assertFalse(viewer.can_modify())
        with self.assertRaises(PermissionError):
            self.sync.sync_findings("dummy_sha", [{"title": "test"}], viewer)

    def test_artifact_and_findings_sync_lifecycle(self):
        lead = AuthUserContext(uid="lead_1", email="lead@lab.org", role=UserRole.LEAD_ARCHITECT, tenant_id="tenant_x")
        sha = "a" * 64
        doc = self.sync.sync_artifact(
            sha256=sha,
            filename="sample.elf",
            size_bytes=1024,
            format_name="ELF",
            architecture="x86_64",
            entropy=5.8,
            overall_posture="CLEAN",
            user=lead,
        )
        self.assertEqual(doc.sha256, sha)
        self.assertEqual(doc.tenant_id, "tenant_x")

        # Sync findings
        findings = [
            {"finding_id": "F-01", "cwe_id": "CWE-120", "title": "strcpy", "severity": "HIGH", "cvss_score": 7.5},
            {"finding_id": "F-02", "cwe_id": "CWE-416", "title": "UAF", "severity": "HIGH", "cvss_score": 8.0},
        ]
        count = self.sync.sync_findings(sha, findings, lead)
        self.assertEqual(count, 2)

        # Retrieve and verify (with tenant context)
        retrieved_art = self.sync.get_artifact(sha, user=lead)
        self.assertIsNotNone(retrieved_art)
        self.assertEqual(retrieved_art["findings_count"], 2)

        retrieved_f = self.sync.get_findings(sha, user=lead)
        self.assertEqual(len(retrieved_f), 2)
        self.assertEqual(retrieved_f[0]["cwe_id"], "CWE-120")

    def test_multi_tenant_artifact_isolation(self):
        """Cross-tenant isolation: Tenant B cannot access Tenant A's artifacts or findings."""
        user_a = AuthUserContext(uid="alice", email="alice@corp.com", role=UserRole.ANALYST, tenant_id="tenant_alpha")
        user_b = AuthUserContext(uid="bob", email="bob@evil.com", role=UserRole.ANALYST, tenant_id="tenant_beta")

        sha = "c" * 64
        self.sync.sync_artifact(
            sha256=sha,
            filename="classified.bin",
            size_bytes=512,
            format_name="PE",
            architecture="x86_64",
            entropy=6.1,
            overall_posture="VULNERABLE",
            user=user_a,
        )
        self.sync.sync_findings(sha, [{"title": "Secret Key Leak", "severity": "CRITICAL"}], user_a)

        # Alice from tenant_alpha CAN access
        self.assertIsNotNone(self.sync.get_artifact(sha, user=user_a))
        self.assertEqual(len(self.sync.get_findings(sha, user=user_a)), 1)

        # Bob from tenant_beta CANNOT access Alice's artifact or findings
        self.assertIsNone(self.sync.get_artifact(sha, user=user_b))
        self.assertEqual(len(self.sync.get_findings(sha, user=user_b)), 0)

    def test_binary_and_report_archival(self):
        analyst = AuthUserContext(uid="a_1", email="a@lab.org", role=UserRole.ANALYST, tenant_id="lab_sec")
        sha = "b" * 64
        data = b"\x7fELFtestbinarypayload"
        storage_url = self.sync.archive_binary(sha, "target.elf", data, analyst)
        self.assertTrue(storage_url.startswith("gs://"))
        self.assertIn("lab_sec", storage_url)
        self.assertIn(sha, storage_url)

        # Archive SARIF report
        sarif_json = '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"}'
        sarif_url = self.sync.archive_report(sha, "sarif", sarif_json, analyst)
        self.assertTrue(sarif_url.endswith(".sarif"))

    def test_analysis_job_lifecycle(self):
        user = AuthUserContext(uid="u_99", email="op@corp.com", role=UserRole.ANALYST, tenant_id="corp_lab")
        job = self.sync.create_analysis_job("dummy_sha_1234", "DEEP_FORENSIC", user)
        self.assertTrue(job.job_id.startswith("job_"))
        self.assertEqual(job.status, "QUEUED")

        # Update progress
        ok = self.sync.update_job_progress(job.job_id, "RUNNING", 50, "DECOMPILING", user=user)
        self.assertTrue(ok)
        j_doc = self.sync.get_job(job.job_id, user=user)
        self.assertEqual(j_doc["status"], "RUNNING")
        self.assertEqual(j_doc["progress_pct"], 50)
        self.assertEqual(j_doc["current_stage"], "DECOMPILING")

    def test_sync_status_honest_backend_reporting(self):
        """get_sync_status accurately reports simulation adapter vs cloud backend."""
        status = self.sync.get_sync_status()
        self.assertIn("backend_type", status)
        self.assertEqual(status["backend_type"], "local_simulation")
        self.assertEqual(status["mode"], "in_memory_simulation")


if __name__ == "__main__":
    unittest.main()
