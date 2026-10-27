"""
Unit & Integration Tests for Firebase Cloud Sync Module (Dimension 2: Backend Architecture & Firebase)
"""

import base64
import json
import unittest

from reverse_forge.firebase_sync import (
    AuthUserContext,
    FirebaseAuthManager,
    FirebaseSyncManager,
    UserRole,
)


class TestFirebaseSyncEngine(unittest.TestCase):
    def setUp(self):
        self.sync = FirebaseSyncManager(project_id="test-reverse-forge")
        self.auth = self.sync.auth

    def test_mock_auth_fallback(self):
        user = self.auth.verify_bearer_token(None)
        self.assertIsNotNone(user)
        self.assertEqual(user.role, UserRole.LEAD_ARCHITECT)
        self.assertTrue(user.can_modify())
        self.assertTrue(user.is_lead())

    def test_bearer_jwt_decoding_and_rbac(self):
        # Create a mock JWT with ANALYST role
        header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("utf-8").rstrip("=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "user_123", "email": "analyst@lab.org", "role": "ANALYST", "tenant_id": "lab_a"}).encode("utf-8")
        ).decode("utf-8").rstrip("=")
        fake_jwt = f"{header}.{payload}."

        user = self.auth.verify_bearer_token(f"Bearer {fake_jwt}")
        self.assertIsNotNone(user)
        self.assertEqual(user.uid, "user_123")
        self.assertEqual(user.email, "analyst@lab.org")
        self.assertEqual(user.role, UserRole.ANALYST)
        self.assertEqual(user.tenant_id, "lab_a")
        self.assertTrue(user.can_modify())
        self.assertFalse(user.is_lead())

    def test_viewer_role_cannot_modify_findings(self):
        viewer = AuthUserContext(uid="view_1", email="view@lab.org", role=UserRole.VIEWER)
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

        # Retrieve and verify
        retrieved_art = self.sync.get_artifact(sha)
        self.assertIsNotNone(retrieved_art)
        self.assertEqual(retrieved_art["findings_count"], 2)

        retrieved_f = self.sync.get_findings(sha)
        self.assertEqual(len(retrieved_f), 2)
        self.assertEqual(retrieved_f[0]["cwe_id"], "CWE-120")

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
        user = AuthUserContext(uid="u_99", email="op@corp.com", role=UserRole.ANALYST)
        sha = "c" * 64
        job = self.sync.create_analysis_job(sha, "12_STAGE_PIPELINE", user)
        self.assertEqual(job.status, "QUEUED")
        self.assertEqual(job.progress_pct, 0)

        # Update to RUNNING
        self.sync.update_job_progress(job.job_id, status="RUNNING", progress_pct=50, stage="DECOMPILATION")
        updated = self.sync.get_job(job.job_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "RUNNING")
        self.assertEqual(updated["progress_pct"], 50)
        self.assertEqual(updated["current_stage"], "DECOMPILATION")

        # Complete job
        self.sync.update_job_progress(job.job_id, status="COMPLETED", progress_pct=100, stage="REPORTING", result_summary={"findings": 3})
        final_job = self.sync.get_job(job.job_id)
        self.assertEqual(final_job["status"], "COMPLETED")
        self.assertEqual(final_job["progress_pct"], 100)
        self.assertEqual(final_job["result_summary"]["findings"], 3)


if __name__ == "__main__":
    unittest.main()
