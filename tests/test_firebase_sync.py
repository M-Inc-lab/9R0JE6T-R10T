"""
Unit & Integration Tests for Firebase Cloud Sync Module (Dimension 2: Backend Architecture & Firebase)
Updated for Stage 2, Stage 4 & Phase 4.1: Cryptographic JWT verification, unforgeable identity seals,
fail-closed auth, strict persistence validation, and tenant isolation.
"""

import os
import time
import unittest
from unittest.mock import MagicMock, patch

from reverse_forge.firebase_sync import (
    AuthUserContext,
    FirebaseAuthManager,
    FirebaseSyncManager,
    LocalSimulationPersistenceAdapter,
    PersistencePermissionError,
    PersistenceUnavailableError,
    ProductionFirestoreStorageAdapter,
    SharedRevocationStore,
    UserRole,
    jwt,
)


class TestFirebaseSyncEngine(unittest.TestCase):
    def setUp(self):
        self.sync = FirebaseSyncManager(project_id="test-reverse-forge", force_local_sim=True)
        self.auth = self.sync.auth
        self.test_secret = "test-secret-key-32-bytes-minimum-length-for-hmac-sha256"
        self.auth.verification_key = self.test_secret
        self.auth.allowed_algorithms = ["HS256"]
        self.auth.allow_dev_mock = True

    def test_mock_auth_fallback_in_dev_mode(self):
        """In development mode, mock auth provides unverified VIEWER context."""
        user = self.auth.verify_bearer_token(None)
        self.assertIsNotNone(user)
        self.assertEqual(user.role, UserRole.VIEWER)
        self.assertFalse(user.is_verified)
        self.assertFalse(user.is_cryptographically_verified())
        self.assertFalse(user.can_modify())
        self.assertFalse(user.is_lead())

    def test_bearer_jwt_cryptographic_verification_and_rbac(self):
        """Verify signed JWT with valid claims is decoded and verified cryptographically."""
        payload = {
            "sub": "user_123",
            "email": "analyst@lab.org",
            "role": "ANALYST",
            "tenant_id": "lab_a",
            "exp": time.time() + 3600,
            "aud": "test-reverse-forge",
            "iss": "https://securetoken.google.com/test-reverse-forge",
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
        self.assertTrue(user.is_cryptographically_verified())

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
            "iss": "https://securetoken.google.com/test-reverse-forge",
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
        viewer = self.auth.issue_verified_context(
            uid="view_1",
            email="view@lab.org",
            role=UserRole.VIEWER,
            tenant_id="tenant_x",
        )
        self.assertTrue(viewer.is_cryptographically_verified())
        self.assertFalse(viewer.can_modify())
        with self.assertRaises(PermissionError):
            self.sync.sync_findings("a" * 64, [{"title": "test"}], viewer)

    def test_direct_auth_user_context_construction_cannot_forge_verification(self):
        """Phase 4.1 §4: Constructing AuthUserContext(..., is_verified=True) directly is unsealed and rejected."""
        forged = AuthUserContext(
            uid="forged_admin",
            email="forged@evil.org",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant_x",
            is_verified=True,
        )
        self.assertFalse(forged.is_verified)
        self.assertFalse(forged.is_cryptographically_verified())
        self.assertFalse(forged.can_modify())
        self.assertFalse(forged.is_lead())
        with self.assertRaises(PermissionError):
            self.sync.sync_findings("a" * 64, [{"title": "test"}], forged)

    def test_artifact_and_findings_sync_lifecycle(self):
        lead = self.auth.issue_verified_context(
            uid="lead_1",
            email="lead@lab.org",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant_x",
        )
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
        user_a = self.auth.issue_verified_context(
            uid="alice", email="alice@corp.com", role=UserRole.ANALYST, tenant_id="tenant_alpha"
        )
        user_b = self.auth.issue_verified_context(
            uid="bob", email="bob@evil.com", role=UserRole.ANALYST, tenant_id="tenant_beta"
        )

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

        # Explicit mismatched tenant_id parameter alongside user_b is rejected with PersistencePermissionError
        with self.assertRaises(PersistencePermissionError):
            self.sync.get_artifact(sha, user=user_b, tenant_id="tenant_alpha")

    def test_binary_and_report_archival(self):
        analyst = self.auth.issue_verified_context(
            uid="a_1", email="a@lab.org", role=UserRole.ANALYST, tenant_id="lab_sec"
        )
        sha = "b" * 64
        data = b"\x7fELFtestbinarypayload"
        # Archive binary
        storage_url = self.sync.archive_binary(sha, "target.elf", data, analyst)
        self.assertTrue(storage_url.startswith("local-sim://"))
        self.assertIn("lab_sec", storage_url)
        self.assertIn(sha, storage_url)

        # Archive SARIF report
        sarif_json = '{"$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"}'
        sarif_url = self.sync.archive_report(sha, "sarif", sarif_json, analyst)
        self.assertTrue(sarif_url.endswith(".sarif"))
        self.assertTrue(sarif_url.startswith("local-sim://"))

    def test_analysis_job_lifecycle(self):
        user = self.auth.issue_verified_context(
            uid="u_99", email="op@corp.com", role=UserRole.ANALYST, tenant_id="corp_lab"
        )
        sha = "d" * 64
        job = self.sync.create_analysis_job(sha, "DEEP_FORENSIC", user)
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

    # ==========================================================================
    # PHASE B: 14 MANDATORY AUTHENTICATION REGRESSION TESTS
    # ==========================================================================

    def _make_valid_claims(self, **overrides):
        now = time.time()
        claims = {
            "sub": "user_verified_123",
            "email": "analyst@reverse-forge.cloud",
            "role": "ANALYST",
            "tenant_id": "tenant_trusted_lab",
            "iss": "https://securetoken.google.com/test-reverse-forge",
            "aud": "test-reverse-forge",
            "exp": now + 3600,
            "nbf": now - 10,
            "jti": "jti_token_001",
        }
        claims.update(overrides)
        return claims

    def test_b1_valid_correctly_signed_token(self):
        """1. Valid, correctly signed token accepted with is_verified=True."""
        claims = self._make_valid_claims()
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        user = self.auth.verify_bearer_token(f"Bearer {token}")
        self.assertIsNotNone(user)
        self.assertTrue(user.is_verified)
        self.assertTrue(user.is_cryptographically_verified())
        self.assertEqual(user.uid, "user_verified_123")
        self.assertEqual(user.role, UserRole.ANALYST)
        self.assertTrue(user.can_modify())

    def test_b2_tampered_signature(self):
        """2. Tampered signature rejected (returns None)."""
        claims = self._make_valid_claims()
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        tampered = token[:-4] + ("BBBB" if token[-4:] != "BBBB" else "CCCC")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {tampered}"))

    def test_b3_alg_none(self):
        """3. Token with alg: none strictly rejected."""
        fake = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {fake}"))

    def test_b4_expired_token(self):
        """4. Expired token rejected."""
        claims = self._make_valid_claims(exp=time.time() - 60)
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_b5_future_nbf(self):
        """5. Future nbf token rejected."""
        claims = self._make_valid_claims(nbf=time.time() + 3600)
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_b6_wrong_issuer(self):
        """6. Token with wrong issuer rejected."""
        claims = self._make_valid_claims(iss="https://rogue-idp.attacker.com")
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_b7_wrong_audience(self):
        """7. Token with wrong audience rejected."""
        claims = self._make_valid_claims(aud="unauthorized-project")
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_b8_missing_issuer_or_audience(self):
        """8. Missing required claim (iss or aud) rejected."""
        claims_no_iss = self._make_valid_claims()
        del claims_no_iss["iss"]
        token1 = jwt.encode(claims_no_iss, self.test_secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token1}"))

        claims_no_aud = self._make_valid_claims()
        del claims_no_aud["aud"]
        token2 = jwt.encode(claims_no_aud, self.test_secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token2}"))

    def test_b9_missing_authorization_header(self):
        """9. Missing Authorization header returns None when mock mode is not opted in."""
        prod_auth = FirebaseAuthManager(project_id="prod_proj", allow_dev_mock=False)
        self.assertIsNone(prod_auth.verify_bearer_token(None))
        self.assertIsNone(prod_auth.verify_bearer_token(""))

    def test_b10_fabricated_privileged_role(self):
        """10. Fabricated privileged role without valid signature or unverified context cannot modify."""
        unverified_admin = AuthUserContext(
            uid="attacker",
            email="attacker@evil.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="victim_tenant",
            is_verified=False,
        )
        self.assertFalse(unverified_admin.can_modify())
        self.assertFalse(unverified_admin.is_lead())
        with self.assertRaises(PermissionError):
            self.sync.sync_findings("a" * 64, [{"title": "fake"}], unverified_admin)

    def test_b11_fabricated_tenant_id(self):
        """11. Fabricated tenant ID outside trusted policy rejected."""
        auth_with_policy = FirebaseAuthManager(
            project_id="test-reverse-forge",
            verification_key=self.test_secret,
            allowed_algorithms=["HS256"],
            trusted_tenants={"trusted_tenant_1", "trusted_tenant_2"},
        )
        claims = self._make_valid_claims(tenant_id="untrusted_foreign_tenant")
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        self.assertIsNone(auth_with_policy.verify_bearer_token(f"Bearer {token}"))

    def test_b12_mock_token_presented_in_production(self):
        """12. Mock token presented in production rejected fail-closed."""
        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "production"}):
            prod_auth = FirebaseAuthManager(project_id="prod_proj", verification_key=self.test_secret)
            self.assertIsNone(prod_auth.verify_bearer_token("Bearer mock-token-admin-1234"))
            self.assertIsNone(prod_auth.verify_bearer_token("Bearer dev-token-local"))

    def test_b13_missing_or_invalid_verification_configuration(self):
        """13. Missing verification key in production or invalid configuration rejects tokens fail-closed."""
        prod_no_key = FirebaseAuthManager(project_id="prod_proj", verification_key=None)
        claims = self._make_valid_claims()
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")
        self.assertIsNone(prod_no_key.verify_bearer_token(f"Bearer {token}"))

    def test_b14_revoked_token_rejected(self):
        """14. Revoked token (by jti, token, or uid) rejected fail-closed."""
        claims = self._make_valid_claims(jti="revoked_jti_999", sub="revoked_user_888")
        token = jwt.encode(claims, self.test_secret, algorithm="HS256")

        # Before revocation: valid
        self.assertIsNotNone(self.auth.verify_bearer_token(f"Bearer {token}"))

        # Revoke by JTI
        self.auth.revoke_token("revoked_jti_999")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

        # Test user-level revocation
        claims2 = self._make_valid_claims(jti="clean_jti", sub="revoked_user_888")
        token2 = jwt.encode(claims2, self.test_secret, algorithm="HS256")
        self.auth.revoke_user("revoked_user_888")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token2}"))


if __name__ == "__main__":
    unittest.main()
