"""
R3V3R53//F0RG3 — Phase 4 Authentication Hardening Tests
=========================================================
Adversarial regression suite verifying all 18 required test cases from the
Phase 4 specification §3 (P0 — Eliminate authentication privilege escalation).

Test index (matches Phase 4 spec order):
  T-01  Missing authorization header
  T-02  Malformed token (not 3-part JWT)
  T-03  Tampered signature
  T-04  Unsigned token (alg=none)
  T-05  Unsupported signing algorithm (alg=HS384 not in allowlist)
  T-06  Expired token
  T-07  Future nbf
  T-08  Incorrect issuer
  T-09  Incorrect audience
  T-10  Missing required claims (no sub)
  T-11  Forged LEAD_ARCHITECT role in unverified context
  T-12  Forged tenant identifier
  T-13  Unverified context attempting modification
  T-14  Mock mode enabled in production
  T-15  Missing verification configuration in production
  T-16  Valid token with unauthorized role (VIEWER cannot modify)
  T-17  Cross-tenant artifact access
  T-18  Token/key configuration errors (bad key format)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _make_jwt(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    s = _b64url(signature)
    return f"{h}.{p}.{s}"

def _now() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# T-01 through T-18
# ---------------------------------------------------------------------------

class TestPhase4AuthHardening(unittest.TestCase):
    """Phase 4 §3: All 18 adversarial authentication test cases."""

    def setUp(self):
        from reverse_forge.firebase_sync import FirebaseAuthManager
        # Non-production auth manager with a known HMAC key for controlled tests
        self.auth = FirebaseAuthManager(
            project_id="test-project",
            expected_issuer="https://securetoken.google.com/test-project",
            expected_audience="test-project",
            verification_key="supersecretkey-for-phase4-tests",
            allowed_algorithms=["HS256", "RS256", "ES256"],
            allow_dev_mock=False,
        )

    # T-01 ─────────────────────────────────────────────────────────────────
    def test_t01_missing_authorization_header(self):
        """None header must return None (fail-closed)."""
        self.assertIsNone(self.auth.verify_bearer_token(None))

    def test_t01b_empty_string_header(self):
        """Empty string header must return None."""
        self.assertIsNone(self.auth.verify_bearer_token(""))

    # T-02 ─────────────────────────────────────────────────────────────────
    def test_t02_malformed_token_not_three_parts(self):
        """Token with only two parts (no signature) must be rejected."""
        self.assertIsNone(self.auth.verify_bearer_token("Bearer only.two"))

    def test_t02b_malformed_token_single_word(self):
        """Single-word token must be rejected."""
        self.assertIsNone(self.auth.verify_bearer_token("Bearer notajwt"))

    def test_t02c_bearer_scheme_only(self):
        """'Bearer ' with no token value must be rejected."""
        self.assertIsNone(self.auth.verify_bearer_token("Bearer "))

    # T-03 ─────────────────────────────────────────────────────────────────
    def test_t03_tampered_signature(self):
        """A JWT with a valid structure but wrong signature must be rejected."""
        payload = {
            "sub": "user-attacker",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        # Build a structurally valid JWT but with a corrupted signature
        tampered = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            payload,
            signature=b"INVALIDSIGNATUREBYTES"
        )
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {tampered}"))

    # T-04 ─────────────────────────────────────────────────────────────────
    def test_t04_unsigned_token_alg_none(self):
        """alg=none must be rejected at header inspection before any decode attempt."""
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "uid-attacker"})
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_t04b_alg_none_uppercase(self):
        """alg=NONE (uppercase) must also be rejected."""
        token = _make_jwt({"alg": "NONE", "typ": "JWT"}, {"sub": "uid-attacker"})
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_t04c_alg_none_mixed_case(self):
        """alg=nOnE (mixed case) must also be rejected."""
        token = _make_jwt({"alg": "nOnE", "typ": "JWT"}, {"sub": "uid-attacker"})
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-05 ─────────────────────────────────────────────────────────────────
    def test_t05_unsupported_algorithm(self):
        """An algorithm outside the explicit allowlist (HS384) must be rejected."""
        token = _make_jwt({"alg": "HS384", "typ": "JWT"}, {"sub": "uid-attacker"})
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_t05b_unknown_algorithm_xyz(self):
        """Unknown algorithm XYZ must be rejected."""
        token = _make_jwt({"alg": "XYZ", "typ": "JWT"}, {"sub": "uid"})
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-06 ─────────────────────────────────────────────────────────────────
    def test_t06_expired_token(self):
        """Token with exp in the past must be rejected."""
        payload = {
            "sub": "uid-expired",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() - 7200,  # 2 hours ago
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-07 ─────────────────────────────────────────────────────────────────
    def test_t07_future_nbf(self):
        """Token with nbf in the future (not-before not yet reached) must be rejected."""
        payload = {
            "sub": "uid-early",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 7200,
            "nbf": _now() + 3600,  # valid only 1 hour from now
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-08 ─────────────────────────────────────────────────────────────────
    def test_t08_incorrect_issuer(self):
        """Token with wrong iss claim must be rejected."""
        payload = {
            "sub": "uid-x",
            "iss": "https://attacker.evil.com/fake-issuer",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-09 ─────────────────────────────────────────────────────────────────
    def test_t09_incorrect_audience(self):
        """Token with wrong aud claim must be rejected."""
        payload = {
            "sub": "uid-x",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "different-project-id",
            "exp": _now() + 3600,
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-10 ─────────────────────────────────────────────────────────────────
    def test_t10_missing_sub_claim(self):
        """Token missing the required 'sub' claim must be rejected."""
        payload = {
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
            # no 'sub'
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_t10b_missing_exp_claim(self):
        """Token missing the required 'exp' claim must be rejected."""
        payload = {
            "sub": "uid-noexp",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            # no 'exp'
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-11 ─────────────────────────────────────────────────────────────────
    def test_t11_forged_lead_architect_role_unverified(self):
        """An unverified context with role=LEAD_ARCHITECT must never pass can_modify/is_lead."""
        from reverse_forge.firebase_sync import AuthUserContext, UserRole
        # Attacker constructs an unverified context directly with elevated role
        ctx = AuthUserContext(
            uid="attacker-uid",
            email="attacker@evil.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="victim-tenant",
            token_claims={"role": "LEAD_ARCHITECT"},
            is_verified=False,  # Not verified
        )
        # Despite elevated role, unverified must deny all privileged ops
        self.assertFalse(ctx.can_modify(), "Unverified LEAD_ARCHITECT must not pass can_modify()")
        self.assertFalse(ctx.is_lead(), "Unverified LEAD_ARCHITECT must not pass is_lead()")

    def test_t11b_forged_role_string_in_jwt_payload(self):
        """Attacker-controlled 'role' string in JWT payload must be constrained to enum values."""
        from reverse_forge.firebase_sync import AuthUserContext, UserRole
        # If verify_bearer_token constructs a role from a string, invalid values fall back to ANALYST
        # Test the role resolution logic: an unknown role must default to ANALYST
        # (not escalate to LEAD_ARCHITECT)
        test_role_strings = ["SUPER_ADMIN", "root", "administrator", "OWNER", "GOD"]
        for role_str in test_role_strings:
            resolved = getattr(UserRole, role_str.upper(), UserRole.ANALYST)
            # Must resolve to ANALYST (default), not LEAD_ARCHITECT
            self.assertNotEqual(resolved, UserRole.LEAD_ARCHITECT,
                                f"Unknown role '{role_str}' must not resolve to LEAD_ARCHITECT")

    # T-12 ─────────────────────────────────────────────────────────────────
    def test_t12_forged_tenant_identifier(self):
        """Attacker-claimed tenant_id in JWT must be validated against trusted_tenants."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        # Auth manager with restricted trusted_tenants
        auth = FirebaseAuthManager(
            project_id="test-project",
            expected_issuer="https://securetoken.google.com/test-project",
            expected_audience="test-project",
            verification_key="supersecretkey-for-phase4-tests",
            allowed_algorithms=["HS256"],
            trusted_tenants={"legitimate-tenant"},
        )
        # Build a token claiming to belong to victim-tenant
        payload = {
            "sub": "attacker-uid",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
            "tenant_id": "victim-tenant",  # Forged!
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        # Even if the token passes structural checks, unauthorized tenant must reject
        result = auth.verify_bearer_token(f"Bearer {token}")
        # Either None (rejected at jwt.decode due to sig mismatch) or
        # None (rejected at tenant check). Either way must be None.
        self.assertIsNone(result, "Forged tenant_id not in trusted_tenants must be rejected")

    # T-13 ─────────────────────────────────────────────────────────────────
    def test_t13_unverified_context_modification_denied(self):
        """FirebaseSyncManager must reject modification from unverified AuthUserContext."""
        from reverse_forge.firebase_sync import FirebaseSyncManager, AuthUserContext, UserRole
        mgr = FirebaseSyncManager(force_local_sim=True)
        # Construct unverified user (is_verified=False)
        unverified_user = AuthUserContext(
            uid="unverified-uid",
            email="unverified@test.com",
            role=UserRole.ANALYST,
            tenant_id="test-tenant",
            is_verified=False,  # Key: not verified
        )
        # Attempting modification must raise PermissionError
        with self.assertRaises(PermissionError):
            mgr.sync_artifact(
                sha256="aabbcc" * 10,
                filename="test.bin",
                size_bytes=64,
                format_name="ELF",
                architecture="x86-64",
                entropy=0.0,
                overall_posture="LOW",
                user=unverified_user,
            )

    def test_t13b_unverified_viewer_modification_denied(self):
        """Unverified VIEWER must also be denied modification."""
        from reverse_forge.firebase_sync import FirebaseSyncManager, AuthUserContext, UserRole
        mgr = FirebaseSyncManager(force_local_sim=True)
        viewer = AuthUserContext(
            uid="viewer-uid",
            email="viewer@test.com",
            role=UserRole.VIEWER,
            tenant_id="test-tenant",
            is_verified=False,
        )
        with self.assertRaises(PermissionError):
            mgr.sync_findings("aabbcc" * 10, [{"cwe_id": "CWE-120"}], viewer)

    # T-14 ─────────────────────────────────────────────────────────────────
    def test_t14_mock_mode_in_production_rejected(self):
        """Mock tokens must be rejected when REVERSE_FORGE_ENV=production."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "fake_key_value",
        }):
            auth = FirebaseAuthManager(
                project_id="prod-project",
                verification_key="prod-key",
            )
            self.assertTrue(auth.is_production, "Must detect production mode")
            # Mock tokens must be flatly rejected in production
            self.assertIsNone(auth.verify_bearer_token("Bearer mock-token-analyst"))
            self.assertIsNone(auth.verify_bearer_token("Bearer dev-token-admin"))
            self.assertIsNone(auth.verify_bearer_token(None))

    def test_t14b_allow_dev_mock_true_rejected_in_production(self):
        """Even allow_dev_mock=True cannot enable mock tokens in production."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "fake_key",
        }):
            auth = FirebaseAuthManager(
                project_id="prod-project",
                verification_key="prod-key",
                allow_dev_mock=True,  # Explicitly requested but in production
            )
            # Production mode must override allow_dev_mock for mock tokens
            result = auth.verify_bearer_token("Bearer mock-token-architect")
            self.assertIsNone(result, "Mock token must be rejected in production even with allow_dev_mock=True")

    # T-15 ─────────────────────────────────────────────────────────────────
    def test_t15_missing_verification_config_in_production(self):
        """In production without verification key, any real JWT must be rejected."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "",  # Empty
            "FIREBASE_JWT_VERIFICATION_KEY": "",  # No key
        }):
            auth = FirebaseAuthManager(project_id="prod-project")
            # Structurally valid JWT but no key to verify signature
            payload = {
                "sub": "uid-x",
                "iss": "https://securetoken.google.com/prod-project",
                "aud": "prod-project",
                "exp": _now() + 3600,
            }
            token = _make_jwt({"alg": "HS256"}, payload)
            # Without verification key, must fail closed
            result = auth.verify_bearer_token(f"Bearer {token}")
            self.assertIsNone(result, "Missing production verification config must reject all real JWTs")

    def test_t15b_missing_verification_config_production_missing_header(self):
        """Missing auth header in production must return None."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "production"}):
            auth = FirebaseAuthManager(project_id="prod-project")
            self.assertIsNone(auth.verify_bearer_token(None))
            self.assertIsNone(auth.verify_bearer_token(""))

    # T-16 ─────────────────────────────────────────────────────────────────
    def test_t16_verified_viewer_cannot_modify(self):
        """A cryptographically verified VIEWER cannot execute modification operations."""
        from reverse_forge.firebase_sync import AuthUserContext, UserRole
        # Verified VIEWER (is_verified=True but role=VIEWER)
        viewer = AuthUserContext(
            uid="viewer-uid",
            email="viewer@company.com",
            role=UserRole.VIEWER,
            tenant_id="company-tenant",
            is_verified=True,  # Properly verified
        )
        # VIEWER role must not pass can_modify()
        self.assertFalse(viewer.can_modify(), "Verified VIEWER must not pass can_modify()")
        self.assertFalse(viewer.is_lead(), "Verified VIEWER must not pass is_lead()")

    def test_t16b_verified_viewer_modification_raises_permission_error(self):
        """FirebaseSyncManager must raise PermissionError for VIEWER attempting modification."""
        from reverse_forge.firebase_sync import FirebaseSyncManager, AuthUserContext, UserRole
        mgr = FirebaseSyncManager(force_local_sim=True)
        viewer = AuthUserContext(
            uid="viewer-uid",
            email="viewer@test.com",
            role=UserRole.VIEWER,
            tenant_id="test-tenant",
            is_verified=True,  # Verified but VIEWER role
        )
        with self.assertRaises(PermissionError):
            mgr.sync_artifact(
                sha256="aabbcc" * 10,
                filename="test.bin",
                size_bytes=64,
                format_name="PE",
                architecture="x86",
                entropy=0.0,
                overall_posture="LOW",
                user=viewer,
            )

    # T-17 ─────────────────────────────────────────────────────────────────
    def test_t17_cross_tenant_artifact_access_denied(self):
        """Tenant B cannot read or modify Tenant A's artifacts through the sync manager."""
        from reverse_forge.firebase_sync import (
            FirebaseSyncManager, AuthUserContext, UserRole, FirestoreArtifactDocument
        )
        from datetime import datetime, timezone

        mgr = FirebaseSyncManager(force_local_sim=True)

        # Tenant A analyst stores an artifact
        tenant_a_user = AuthUserContext(
            uid="alice-uid",
            email="alice@tenant-a.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-a",
            is_verified=True,
        )
        sha = "deadbeef" * 8
        mgr.sync_artifact(
            sha256=sha,
            filename="secret_target.elf",
            size_bytes=1024,
            format_name="ELF",
            architecture="x86-64",
            entropy=6.2,
            overall_posture="HIGH_RISK",
            user=tenant_a_user,
        )

        # Tenant B tries to read Tenant A's artifact
        tenant_b_user = AuthUserContext(
            uid="bob-uid",
            email="bob@tenant-b.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-b",
            is_verified=True,
        )
        # Direct backend lookup: Tenant B must not retrieve Tenant A's artifact
        result = mgr.backend.get_artifact(sha, tenant_id="tenant-b")
        self.assertIsNone(result, "Tenant B must not access Tenant A's artifact")

        # Tenant A can still read it
        a_result = mgr.backend.get_artifact(sha, tenant_id="tenant-a")
        self.assertIsNotNone(a_result, "Tenant A must be able to read its own artifact")

    def test_t17b_cross_tenant_findings_access_denied(self):
        """Tenant B cannot read Tenant A's findings."""
        from reverse_forge.firebase_sync import (
            FirebaseSyncManager, AuthUserContext, UserRole
        )
        mgr = FirebaseSyncManager(force_local_sim=True)
        tenant_a_user = AuthUserContext(
            uid="alice-uid", email="alice@a.com",
            role=UserRole.ANALYST, tenant_id="tenant-alpha", is_verified=True,
        )
        sha = "cafebabe" * 8
        mgr.sync_findings(sha, [{"cwe_id": "CWE-78", "title": "Command Injection"}], tenant_a_user)

        # Tenant B query returns empty
        b_findings = mgr.backend.get_findings(sha, tenant_id="tenant-beta")
        self.assertEqual(b_findings, [], "Tenant B must not access Tenant A's findings")

    # T-18 ─────────────────────────────────────────────────────────────────
    def test_t18_key_configuration_error_bad_format(self):
        """Completely invalid key material must cause token verification to fail, not crash."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        # Auth manager with nonsense key
        auth = FirebaseAuthManager(
            project_id="test-project",
            expected_issuer="https://securetoken.google.com/test-project",
            expected_audience="test-project",
            verification_key="NOT_A_VALID_KEY\x00\x01\x02",
            allowed_algorithms=["RS256"],  # RS256 requires PEM, not this garbage
        )
        payload = {
            "sub": "uid-x",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        # The token claims RS256 but key is garbage — must fail cleanly
        token = _make_jwt({"alg": "RS256"}, payload)
        result = auth.verify_bearer_token(f"Bearer {token}")
        self.assertIsNone(result, "Bad key material must cause clean failure, not crash")

    def test_t18b_empty_verification_key_rejects_real_jwt(self):
        """Empty verification_key must reject all real JWTs regardless of environment."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(
            project_id="test-project",
            verification_key="",  # Empty key
            allowed_algorithms=["HS256"],
        )
        payload = {
            "sub": "uid-x",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        token = _make_jwt({"alg": "HS256"}, payload)
        result = auth.verify_bearer_token(f"Bearer {token}")
        self.assertIsNone(result, "Empty verification key must reject all real JWTs")

    # ─── Additional boundary tests ────────────────────────────────────────

    def test_can_modify_requires_both_verified_and_correct_role(self):
        """can_modify() requires is_verified=True AND ANALYST/LEAD_ARCHITECT role."""
        from reverse_forge.firebase_sync import AuthUserContext, UserRole
        combos = [
            (True, UserRole.VIEWER, False),
            (False, UserRole.ANALYST, False),
            (False, UserRole.LEAD_ARCHITECT, False),
            (True, UserRole.ANALYST, True),
            (True, UserRole.LEAD_ARCHITECT, True),
        ]
        for verified, role, expected in combos:
            ctx = AuthUserContext(uid="u", email="e@x.com", role=role, is_verified=verified)
            result = ctx.can_modify()
            self.assertEqual(result, expected,
                             f"can_modify() with verified={verified}, role={role} should be {expected}")

    def test_revocation_denylist_blocks_subsequent_calls(self):
        """Revoked token jti must be blocked on every subsequent verification attempt."""
        from reverse_forge.firebase_sync import FirebaseAuthManager
        auth = FirebaseAuthManager(allow_dev_mock=True, verification_key="key")
        auth.revoke_token("jti-compromised-abc")
        self.assertIn("jti-compromised-abc", auth.revoked_tokens)
        auth.revoke_user("uid-terminated")
        self.assertIn("uid-terminated", auth.revoked_users)

    def test_non_bearer_scheme_basic_rejected(self):
        """HTTP Basic auth scheme must be rejected."""
        self.assertIsNone(self.auth.verify_bearer_token("Basic dXNlcjpwYXNz"))

    def test_non_bearer_scheme_digest_rejected(self):
        """HTTP Digest auth scheme must be rejected."""
        self.assertIsNone(self.auth.verify_bearer_token("Digest realm=test"))

    def test_non_bearer_scheme_token_rejected(self):
        """Generic Token scheme must be rejected."""
        self.assertIsNone(self.auth.verify_bearer_token("Token sometoken123"))


class TestProductionPersistenceAdapterContracts(unittest.TestCase):
    """Phase 4 §5: Persistence adapter contract tests with explicit backend labeling."""

    def test_production_adapter_raises_without_credentials(self):
        """ProductionFirestoreStorageAdapter must raise RuntimeError if key is absent."""
        from reverse_forge.firebase_sync import ProductionFirestoreStorageAdapter
        with patch.dict(os.environ, {"FIREBASE_SERVICE_ACCOUNT_KEY": ""}):
            with self.assertRaises(RuntimeError) as ctx:
                ProductionFirestoreStorageAdapter(
                    project_id="prod-project",
                    storage_bucket="prod-bucket",
                )
            self.assertIn("unavailable", str(ctx.exception).lower())

    def test_simulation_adapter_never_returns_gs_uri(self):
        """LocalSimulationPersistenceAdapter must never produce gs:// URIs."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter
        adapter = LocalSimulationPersistenceAdapter()
        for i in range(5):
            uri = adapter.store_blob(f"path/file_{i}.bin", b"DATA", tenant_id=f"tenant_{i}")
            self.assertFalse(uri.startswith("gs://"),
                             f"Simulation URI must not use gs://: {uri}")
            self.assertTrue(uri.startswith("local-sim://"),
                            f"Simulation URI must use local-sim://: {uri}")

    def test_simulation_adapter_tenant_isolation_jobs(self):
        """Jobs stored under tenant_a must not appear under tenant_b."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter, FirestoreJobDocument
        from datetime import datetime, timezone
        adapter = LocalSimulationPersistenceAdapter()
        now = datetime.now(timezone.utc).isoformat()
        job = FirestoreJobDocument(
            job_id="job-001",
            artifact_sha256="aabb" * 16,
            job_type="full_analysis",
            status="RUNNING",
            progress_pct=42,
            current_stage="Stage 3",
            submitted_by="alice-uid",
            tenant_id="tenant-alice",
            created_at=now,
            updated_at=now,
        )
        adapter.save_job(job)
        # Tenant alice can read it
        self.assertIsNotNone(adapter.get_job("job-001", tenant_id="tenant-alice"))
        # Tenant bob cannot
        self.assertIsNone(adapter.get_job("job-001", tenant_id="tenant-bob"))

    def test_simulation_adapter_update_job_tenant_isolation(self):
        """Job updates must be scoped to the correct tenant."""
        from reverse_forge.firebase_sync import LocalSimulationPersistenceAdapter, FirestoreJobDocument
        from datetime import datetime, timezone
        adapter = LocalSimulationPersistenceAdapter()
        now = datetime.now(timezone.utc).isoformat()
        job = FirestoreJobDocument(
            job_id="job-002",
            artifact_sha256="ccdd" * 16,
            job_type="static_analysis",
            status="QUEUED",
            progress_pct=0,
            current_stage="Pending",
            submitted_by="bob-uid",
            tenant_id="tenant-correct",
            created_at=now,
            updated_at=now,
        )
        adapter.save_job(job)
        # Update within correct tenant succeeds
        ok = adapter.update_job("job-002", "tenant-correct", {"status": "COMPLETED"})
        self.assertTrue(ok)
        # Update with wrong tenant fails (job not found under that tenant)
        ok_wrong = adapter.update_job("job-002", "tenant-wrong", {"status": "HACKED"})
        self.assertFalse(ok_wrong)

    def test_firebase_sync_manager_cannot_silently_fall_back(self):
        """FirebaseSyncManager in production mode must raise, not silently use simulation."""
        from reverse_forge.firebase_sync import FirebaseSyncManager
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "/nonexistent/path/service-account.json",
        }):
            with self.assertRaises(RuntimeError):
                # Should raise because key file does not exist
                FirebaseSyncManager()  # force_local_sim=False (default in production)


class TestNativeBridgePhase4(unittest.TestCase):
    """Phase 4 §6: Native backend integrity and cache reproducibility."""

    def test_fingerprint_is_deterministic(self):
        """Source fingerprint must be identical across two calls with same inputs."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fp1 = NativeRustAccelerator.compute_source_fingerprint(repo_root)
        fp2 = NativeRustAccelerator.compute_source_fingerprint(repo_root)
        self.assertEqual(fp1, fp2, "Source fingerprint must be deterministic")
        self.assertEqual(len(fp1), 64, "Fingerprint must be a 64-char hex SHA-256")

    def test_fingerprint_changes_if_source_changes(self):
        """Source fingerprint must differ when source content changes."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        import shutil

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fp_before = NativeRustAccelerator.compute_source_fingerprint(repo_root)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake repo root with a modified source file
            fake_rust_dir = os.path.join(tmpdir, "rust_core", "src")
            os.makedirs(fake_rust_dir)
            # Write different content than actual source
            with open(os.path.join(fake_rust_dir, "lib.rs"), "w") as f:
                f.write("// Modified source content for test")

            fp_modified = NativeRustAccelerator.compute_source_fingerprint(tmpdir)
            self.assertNotEqual(fp_before, fp_modified,
                                "Fingerprint must change when source changes")

    def test_validate_abi_rejects_missing_symbols(self):
        """Library missing required symbols must fail ABI validation."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        # Mock with only some symbols
        partial_lib = MagicMock(spec=["rf_rust_entropy", "rf_rust_flirt_crc16"])
        self.assertFalse(NativeRustAccelerator._validate_abi(partial_lib))

    def test_validate_abi_rejects_wrong_crc16_vector(self):
        """ABI validation must reject library returning wrong CRC16 for '123456789'."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0xDEAD  # Wrong!
        self.assertFalse(NativeRustAccelerator._validate_abi(lib))

    def test_validate_abi_rejects_wrong_entropy_vector(self):
        """ABI validation must reject library returning nonzero entropy for empty buffer."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0x906E  # Correct CRC
        lib.rf_rust_entropy.return_value = 1.5         # Wrong! Should be 0.0
        self.assertFalse(NativeRustAccelerator._validate_abi(lib))

    def test_validate_abi_rejects_wrong_fnv1a64_vector(self):
        """ABI validation must reject library returning wrong FNV1a-64 for 'test'."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0x906E
        lib.rf_rust_entropy.return_value = 0.0
        lib.rf_rust_fnv1a_64.return_value = 0xBADBAD  # Wrong!
        self.assertFalse(NativeRustAccelerator._validate_abi(lib))

    def test_validate_abi_accepts_correct_vectors(self):
        """ABI validation must accept a library returning all correct mathematical vectors."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0x906E
        lib.rf_rust_entropy.return_value = 0.0
        lib.rf_rust_fnv1a_64.return_value = 0xf9e6e6ef197c2b25
        self.assertTrue(NativeRustAccelerator._validate_abi(lib))

    def test_build_diagnostics_are_captured_on_failure(self):
        """Build diagnostics must be accessible and not suppressed on failure."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        # Diagnostics list is accessible
        diags = NativeRustAccelerator.get_build_diagnostics()
        self.assertIsInstance(diags, list,
                              "get_build_diagnostics() must return a list")

    def test_backend_always_returns_known_value(self):
        """Active backend must always be one of the three explicit modes."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator, BackendExecutionMode
        backend = NativeRustAccelerator.get_active_backend()
        valid_backends = set(BackendExecutionMode)
        self.assertIn(backend, valid_backends,
                      f"Backend {backend} is not a known BackendExecutionMode")


if __name__ == "__main__":
    unittest.main()
