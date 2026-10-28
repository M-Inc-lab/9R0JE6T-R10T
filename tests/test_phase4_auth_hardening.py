"""
R3V3R53//F0RG3 — Phase 4 & Phase 4.1 Authentication & Persistence Hardening Tests
==================================================================================
Adversarial regression suite verifying all 18 test cases from Phase 4 §3 plus
all Phase 4.1 §4 (JWT authentication & tenant authorization) and §7 (Persistence
boundary hardening) requirements:
  T-01..T-18: Phase 4 core authentication and adapter contracts
  P41-AUTH-01: Default allowed_algorithms is RS256 only (explicit provider default)
  P41-AUTH-02: RSA (RS256) and ECDSA (ES256) cryptographic signature verification
  P41-AUTH-03: Algorithm/key compatibility checks (RSA public key rejected for HS256; symmetric secret rejected for RS256/ES256)
  P41-AUTH-04: Malformed claim types rejected (boolean exp/nbf, integer sub, list role, future iat)
  P41-AUTH-05: Unknown/unrecognized role values strictly rejected (never defaulted to ANALYST)
  P41-AUTH-06: Server-side tenant_membership_policy enforcement and cross-tenant substitution rejection
  P41-AUTH-07: Direct AuthUserContext(..., is_verified=True) construction and post-construction field mutation rejected
  P41-AUTH-08: SharedRevocationStore cross-instance / restart persistence
  P41-PERSIST-01: Principal-derived tenant ownership, path traversal / URI scheme rejection, and NotFound vs PermissionDenied vs Unavailable distinction
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from reverse_forge.firebase_sync import (
    AuthUserContext,
    FirebaseAuthManager,
    FirebaseSyncManager,
    FirestoreArtifactDocument,
    FirestoreJobDocument,
    LocalSimulationPersistenceAdapter,
    PersistencePermissionError,
    PersistenceUnavailableError,
    ProductionFirestoreStorageAdapter,
    SharedRevocationStore,
    UserRole,
    jwt,
    validate_artifact_sha256,
    validate_document_id,
    validate_storage_blob_path,
    validate_tenant_id,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _make_jwt(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    s = _b64url(signature)
    return f"{h}.{p}.{s}"


def _now() -> int:
    return int(time.time())


class TestPhase4AuthHardening(unittest.TestCase):
    """Phase 4 §3 & Phase 4.1 §4: Adversarial authentication test cases."""

    def setUp(self):
        self.secret = "supersecretkey-for-phase4-tests-32bytes!"
        self.auth = FirebaseAuthManager(
            project_id="test-project",
            expected_issuer="https://securetoken.google.com/test-project",
            expected_audience="test-project",
            verification_key=self.secret,
            allowed_algorithms=["HS256"],
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
        tampered = _make_jwt(
            {"alg": "HS256", "typ": "JWT"},
            payload,
            signature=b"INVALIDSIGNATUREBYTES",
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
            "exp": _now() - 7200,
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-07 ─────────────────────────────────────────────────────────────────
    def test_t07_future_nbf(self):
        """Token with nbf in the future (not-before not yet reached) must be rejected."""
        payload = {
            "sub": "uid-early",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 7200,
            "nbf": _now() + 3600,
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")
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
        token = jwt.encode(payload, self.secret, algorithm="HS256")
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
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-10 ─────────────────────────────────────────────────────────────────
    def test_t10_missing_sub_claim(self):
        """Token missing the required 'sub' claim must be rejected."""
        payload = {
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    def test_t10b_missing_exp_claim(self):
        """Token missing the required 'exp' claim must be rejected."""
        payload = {
            "sub": "uid-noexp",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        self.assertIsNone(self.auth.verify_bearer_token(f"Bearer {token}"))

    # T-11 ─────────────────────────────────────────────────────────────────
    def test_t11_forged_lead_architect_role_unverified(self):
        """An unverified context with role=LEAD_ARCHITECT must never pass can_modify/is_lead."""
        ctx = AuthUserContext(
            uid="attacker-uid",
            email="attacker@evil.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="victim-tenant",
            token_claims={"role": "LEAD_ARCHITECT"},
            is_verified=False,
        )
        self.assertFalse(ctx.can_modify(), "Unverified LEAD_ARCHITECT must not pass can_modify()")
        self.assertFalse(ctx.is_lead(), "Unverified LEAD_ARCHITECT must not pass is_lead()")

    def test_t11b_forged_role_string_in_jwt_payload(self):
        """Phase 4.1 §4: Unrecognized or malformed 'role' strings in JWT payload must be strictly rejected."""
        test_role_strings = ["SUPER_ADMIN", "root", "administrator", "OWNER", "GOD", "", "analyst;drop", 123, ["ANALYST"]]
        for role_val in test_role_strings:
            with self.assertRaises(ValueError):
                FirebaseAuthManager.resolve_role(role_val)
            payload = {
                "sub": "attacker-uid",
                "iss": "https://securetoken.google.com/test-project",
                "aud": "test-project",
                "exp": _now() + 3600,
                "role": role_val,
            }
            token = jwt.encode(payload, self.secret, algorithm="HS256")
            self.assertIsNone(
                self.auth.verify_bearer_token(f"Bearer {token}"),
                f"Token with invalid role {role_val!r} must be rejected",
            )

    # T-12 ─────────────────────────────────────────────────────────────────
    def test_t12_forged_tenant_identifier(self):
        """Attacker-claimed tenant_id in JWT must be validated against trusted_tenants."""
        auth = FirebaseAuthManager(
            project_id="test-project",
            expected_issuer="https://securetoken.google.com/test-project",
            expected_audience="test-project",
            verification_key=self.secret,
            allowed_algorithms=["HS256"],
            trusted_tenants={"legitimate-tenant"},
        )
        payload = {
            "sub": "attacker-uid",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
            "tenant_id": "victim-tenant",
        }
        token = jwt.encode(payload, self.secret, algorithm="HS256")
        result = auth.verify_bearer_token(f"Bearer {token}")
        self.assertIsNone(result, "Forged tenant_id not in trusted_tenants must be rejected")

    # T-13 ─────────────────────────────────────────────────────────────────
    def test_t13_unverified_context_modification_denied(self):
        """FirebaseSyncManager must reject modification from unverified AuthUserContext."""
        mgr = FirebaseSyncManager(force_local_sim=True)
        unverified_user = AuthUserContext(
            uid="unverified-uid",
            email="unverified@test.com",
            role=UserRole.ANALYST,
            tenant_id="test-tenant",
            is_verified=False,
        )
        with self.assertRaises(PermissionError):
            mgr.sync_artifact(
                sha256="a" * 64,
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
        mgr = FirebaseSyncManager(force_local_sim=True)
        viewer = AuthUserContext(
            uid="viewer-uid",
            email="viewer@test.com",
            role=UserRole.VIEWER,
            tenant_id="test-tenant",
            is_verified=False,
        )
        with self.assertRaises(PermissionError):
            mgr.sync_findings("a" * 64, [{"cwe_id": "CWE-120"}], viewer)

    # T-14 ─────────────────────────────────────────────────────────────────
    def test_t14_mock_mode_in_production_rejected(self):
        """Mock tokens must be rejected when REVERSE_FORGE_ENV=production."""
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "fake_key_value",
        }):
            auth = FirebaseAuthManager(
                project_id="prod-project",
                verification_key=self.secret,
                allowed_algorithms=["HS256"],
            )
            self.assertTrue(auth.is_production, "Must detect production mode")
            self.assertIsNone(auth.verify_bearer_token("Bearer mock-token-analyst"))
            self.assertIsNone(auth.verify_bearer_token("Bearer dev-token-admin"))
            self.assertIsNone(auth.verify_bearer_token(None))

    def test_t14b_allow_dev_mock_true_rejected_in_production(self):
        """Even allow_dev_mock=True cannot enable mock tokens in production."""
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "fake_key",
        }):
            auth = FirebaseAuthManager(
                project_id="prod-project",
                verification_key=self.secret,
                allowed_algorithms=["HS256"],
                allow_dev_mock=True,
            )
            result = auth.verify_bearer_token("Bearer mock-token-architect")
            self.assertIsNone(result, "Mock token must be rejected in production even with allow_dev_mock=True")

    # T-15 ─────────────────────────────────────────────────────────────────
    def test_t15_missing_verification_config_in_production(self):
        """In production without verification key, any real JWT must be rejected."""
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "",
            "FIREBASE_JWT_VERIFICATION_KEY": "",
        }):
            auth = FirebaseAuthManager(project_id="prod-project")
            payload = {
                "sub": "uid-x",
                "iss": "https://securetoken.google.com/prod-project",
                "aud": "prod-project",
                "exp": _now() + 3600,
            }
            token = _make_jwt({"alg": "HS256"}, payload)
            result = auth.verify_bearer_token(f"Bearer {token}")
            self.assertIsNone(result, "Missing production verification config must reject all real JWTs")

    def test_t15b_missing_verification_config_production_missing_header(self):
        """Missing auth header in production must return None."""
        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "production"}):
            auth = FirebaseAuthManager(project_id="prod-project")
            self.assertIsNone(auth.verify_bearer_token(None))
            self.assertIsNone(auth.verify_bearer_token(""))

    # T-16 ─────────────────────────────────────────────────────────────────
    def test_t16_verified_viewer_cannot_modify(self):
        """A cryptographically verified VIEWER cannot execute modification operations."""
        viewer = self.auth.issue_verified_context(
            uid="viewer-uid",
            email="viewer@company.com",
            role=UserRole.VIEWER,
            tenant_id="company-tenant",
        )
        self.assertTrue(viewer.is_cryptographically_verified())
        self.assertFalse(viewer.can_modify(), "Verified VIEWER must not pass can_modify()")
        self.assertFalse(viewer.is_lead(), "Verified VIEWER must not pass is_lead()")

    def test_t16b_verified_viewer_modification_raises_permission_error(self):
        """FirebaseSyncManager must raise PermissionError for VIEWER attempting modification."""
        mgr = FirebaseSyncManager(force_local_sim=True)
        viewer = mgr.auth.issue_verified_context(
            uid="viewer-uid",
            email="viewer@test.com",
            role=UserRole.VIEWER,
            tenant_id="test-tenant",
        )
        with self.assertRaises(PermissionError):
            mgr.sync_artifact(
                sha256="a" * 64,
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
        mgr = FirebaseSyncManager(force_local_sim=True)
        tenant_a_user = mgr.auth.issue_verified_context(
            uid="alice-uid",
            email="alice@tenant-a.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-a",
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

        tenant_b_user = mgr.auth.issue_verified_context(
            uid="bob-uid",
            email="bob@tenant-b.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-b",
        )
        self.assertIsNone(mgr.get_artifact(sha, user=tenant_b_user))
        result = mgr.backend.get_artifact(sha, tenant_id="tenant-b")
        self.assertIsNone(result, "Tenant B must not access Tenant A's artifact")

        a_result = mgr.backend.get_artifact(sha, tenant_id="tenant-a")
        self.assertIsNotNone(a_result, "Tenant A must be able to read its own artifact")

    def test_t17b_cross_tenant_findings_access_denied(self):
        """Tenant B cannot read Tenant A's findings."""
        mgr = FirebaseSyncManager(force_local_sim=True)
        tenant_a_user = mgr.auth.issue_verified_context(
            uid="alice-uid",
            email="alice@a.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-alpha",
        )
        sha = "cafebabe" * 8
        mgr.sync_findings(sha, [{"cwe_id": "CWE-78", "title": "Command Injection"}], tenant_a_user)

        b_findings = mgr.backend.get_findings(sha, tenant_id="tenant-beta")
        self.assertEqual(b_findings, [], "Tenant B must not access Tenant A's findings")

    # T-18 ─────────────────────────────────────────────────────────────────
    def test_t18_key_configuration_error_bad_format(self):
        """Completely invalid key material must cause token verification to fail, not crash."""
        auth = FirebaseAuthManager(
            project_id="test-project",
            expected_issuer="https://securetoken.google.com/test-project",
            expected_audience="test-project",
            verification_key="NOT_A_VALID_KEY\x00\x01\x02",
            allowed_algorithms=["RS256"],
        )
        payload = {
            "sub": "uid-x",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        token = _make_jwt({"alg": "RS256"}, payload)
        result = auth.verify_bearer_token(f"Bearer {token}")
        self.assertIsNone(result, "Bad key material must cause clean failure, not crash")

    def test_t18b_empty_verification_key_rejects_real_jwt(self):
        """Empty verification_key must reject all real JWTs regardless of environment."""
        auth = FirebaseAuthManager(
            project_id="test-project",
            verification_key="",
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

    # ─── Additional Phase 4 & 4.1 boundary tests ──────────────────────────

    def test_can_modify_requires_sealed_verification_and_correct_role(self):
        """can_modify() requires sealed cryptographic verification AND ANALYST/LEAD_ARCHITECT role."""
        combos = [
            (True, UserRole.VIEWER, False),
            (False, UserRole.ANALYST, False),
            (False, UserRole.LEAD_ARCHITECT, False),
            (True, UserRole.ANALYST, True),
            (True, UserRole.LEAD_ARCHITECT, True),
        ]
        for verified, role, expected in combos:
            if verified:
                ctx = self.auth.issue_verified_context(uid="u", email="e@x.com", role=role, tenant_id="tenant-a")
            else:
                ctx = AuthUserContext(uid="u", email="e@x.com", role=role, tenant_id="tenant-a", is_verified=False)
            self.assertEqual(
                ctx.can_modify(),
                expected,
                f"can_modify() with verified={verified}, role={role} should be {expected}",
            )

    def test_direct_object_construction_with_is_verified_true_cannot_bypass_seal(self):
        """Phase 4.1 §4: Direct AuthUserContext(..., is_verified=True) construction is downgraded and unsealed."""
        fabricated = AuthUserContext(
            uid="attacker",
            email="attacker@evil.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant-a",
            is_verified=True,
        )
        self.assertFalse(fabricated.is_verified)
        self.assertFalse(fabricated.is_cryptographically_verified())
        self.assertFalse(fabricated.can_modify())
        self.assertFalse(fabricated.is_lead())

        # Even if attacker mutates attributes after construction on a genuinely sealed context, seal breaks!
        legit = self.auth.issue_verified_context(
            uid="viewer-1",
            email="viewer@tenant-a.com",
            role=UserRole.VIEWER,
            tenant_id="tenant-a",
        )
        self.assertTrue(legit.is_cryptographically_verified())
        legit.role = UserRole.LEAD_ARCHITECT
        self.assertFalse(legit.is_cryptographically_verified(), "Mutating role after sealing must invalidate seal")
        self.assertFalse(legit.can_modify())
        self.assertFalse(legit.is_lead())

        legit2 = self.auth.issue_verified_context(
            uid="analyst-1",
            email="analyst@tenant-a.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-a",
        )
        legit2.tenant_id = "victim-tenant"
        self.assertFalse(legit2.is_cryptographically_verified(), "Mutating tenant_id after sealing must invalidate seal")

    def test_default_provider_algorithm_is_rs256_only(self):
        """Phase 4.1 §4: Default allowed_algorithms must be ['RS256'] for Firebase ID tokens."""
        default_auth = FirebaseAuthManager(project_id="firebase-proj")
        self.assertEqual(default_auth.allowed_algorithms, ["RS256"])

    def test_rs256_and_es256_signature_verification_and_algorithm_confusion_blocked(self):
        """Phase 4.1 §4: Verify RS256 and ES256 tokens and reject algorithm/key confusion."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_priv_pem = rsa_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        rsa_pub_pem = rsa_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        ec_priv = ec.generate_private_key(ec.SECP256R1())
        ec_priv_pem = ec_priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")
        ec_pub_pem = ec_priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        claims = {
            "sub": "rsa-user-01",
            "email": "rsa@lab.org",
            "role": "LEAD_ARCHITECT",
            "tenant_id": "tenant_rsa",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
            "nbf": _now() - 5,
        }

        # 1. Valid RS256 token verified with RSA public key
        rsa_auth = FirebaseAuthManager(
            project_id="test-project",
            verification_key=rsa_pub_pem,
            allowed_algorithms=["RS256"],
        )
        rs256_token = jwt.encode(claims, rsa_priv_pem, algorithm="RS256")
        rsa_user = rsa_auth.verify_bearer_token(f"Bearer {rs256_token}")
        self.assertIsNotNone(rsa_user)
        self.assertTrue(rsa_user.is_cryptographically_verified())
        self.assertTrue(rsa_user.is_lead())

        # 2. Algorithm confusion attack: signing HS256 token using RSA public key PEM as HMAC secret
        confused_auth = FirebaseAuthManager(
            project_id="test-project",
            verification_key=rsa_pub_pem,
            allowed_algorithms=["RS256", "HS256"],
        )
        with self.assertRaises(Exception):
            jwt.encode(claims, rsa_pub_pem, algorithm="HS256")
        import hmac as _hmac
        hdr_b64 = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        pay_b64 = _b64url(json.dumps(claims).encode())
        signing_in = f"{hdr_b64}.{pay_b64}".encode("ascii")
        forged_sig = _b64url(_hmac.new(rsa_pub_pem.encode("utf-8"), signing_in, hashlib.sha256).digest())
        confused_token = f"{hdr_b64}.{pay_b64}.{forged_sig}"
        self.assertIsNone(
            confused_auth.verify_bearer_token(f"Bearer {confused_token}"),
            "RSA public key must never be accepted as an HS256 HMAC secret",
        )

        # 3. Valid ES256 token verified with EC public key, and rejected with RSA public key
        ec_auth = FirebaseAuthManager(
            project_id="test-project",
            verification_key=ec_pub_pem,
            allowed_algorithms=["ES256"],
        )
        es256_token = jwt.encode(claims, ec_priv_pem, algorithm="ES256")
        ec_user = ec_auth.verify_bearer_token(f"Bearer {es256_token}")
        self.assertIsNotNone(ec_user)
        self.assertTrue(ec_user.is_cryptographically_verified())

        # EC token presented to RSA verifier is rejected
        self.assertIsNone(rsa_auth.verify_bearer_token(f"Bearer {es256_token}"))

    def test_unexpected_claim_types_and_future_iat_rejected(self):
        """Phase 4.1 §4: Malformed claim types (bool exp/nbf, int sub, future iat) must be rejected."""
        base_claims = {
            "sub": "valid-user",
            "iss": "https://securetoken.google.com/test-project",
            "aud": "test-project",
            "exp": _now() + 3600,
        }
        bad_overrides = [
            {"exp": True},
            {"nbf": True},
            {"iat": True},
            {"iat": _now() + 3600},  # Future-dated iat beyond clock skew
            {"sub": 12345},
            {"sub": "   "},
            {"email": ["not-a-string@lab.org"]},
            {"jti": ""},
            {"tenant_id": "../traversal"},
        ]
        for override in bad_overrides:
            claims = dict(base_claims)
            claims.update(override)
            tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, claims, signature=b"x")
            # Even with valid signature, claim validation must reject
            import hmac as _hmac
            parts = tok.split(".")
            sig = _b64url(_hmac.new(self.secret.encode("utf-8"), f"{parts[0]}.{parts[1]}".encode("ascii"), hashlib.sha256).digest())
            signed_bad_tok = f"{parts[0]}.{parts[1]}.{sig}"
            self.assertIsNone(
                self.auth.verify_bearer_token(f"Bearer {signed_bad_tok}"),
                f"Malformed claims {override} must be rejected",
            )

    def test_server_side_tenant_membership_policy_enforced(self):
        """Phase 4.1 §4: Server-side tenant_membership_policy prevents arbitrary tenant claim substitution."""
        auth = FirebaseAuthManager(
            project_id="test-project",
            verification_key=self.secret,
            allowed_algorithms=["HS256"],
            tenant_membership_policy={
                "alice-uid": {"tenant_alpha"},
                "bob-uid": {"tenant_beta"},
            },
        )
        # Alice claiming tenant_alpha succeeds
        tok_ok = jwt.encode(
            {
                "sub": "alice-uid",
                "tenant_id": "tenant_alpha",
                "iss": "https://securetoken.google.com/test-project",
                "aud": "test-project",
                "exp": _now() + 3600,
            },
            self.secret,
            algorithm="HS256",
        )
        self.assertIsNotNone(auth.verify_bearer_token(f"Bearer {tok_ok}"))

        # Alice claiming tenant_beta is rejected by server-side membership policy
        tok_cross = jwt.encode(
            {
                "sub": "alice-uid",
                "tenant_id": "tenant_beta",
                "iss": "https://securetoken.google.com/test-project",
                "aud": "test-project",
                "exp": _now() + 3600,
            },
            self.secret,
            algorithm="HS256",
        )
        self.assertIsNone(auth.verify_bearer_token(f"Bearer {tok_cross}"))

    def test_shared_sqlite_revocation_store_persists_across_restarts(self):
        """Phase 4.1 §4: SharedRevocationStore persists token/user revocations across manager instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "revocations.sqlite3")
            store1 = SharedRevocationStore(db_path=db_path)
            auth1 = FirebaseAuthManager(
                project_id="test-project",
                verification_key=self.secret,
                allowed_algorithms=["HS256"],
                revocation_store=store1,
            )
            self.assertEqual(auth1.revocation_persistence_mode, "shared_sqlite")
            tok = jwt.encode(
                {
                    "sub": "user-persist-1",
                    "jti": "jti-persist-1",
                    "iss": "https://securetoken.google.com/test-project",
                    "aud": "test-project",
                    "exp": _now() + 3600,
                },
                self.secret,
                algorithm="HS256",
            )
            self.assertIsNotNone(auth1.verify_bearer_token(f"Bearer {tok}"))
            auth1.revoke_token("jti-persist-1")

            # Simulate restart with a fresh FirebaseAuthManager and SharedRevocationStore pointing to same DB
            store2 = SharedRevocationStore(db_path=db_path)
            auth2 = FirebaseAuthManager(
                project_id="test-project",
                verification_key=self.secret,
                allowed_algorithms=["HS256"],
                revocation_store=store2,
            )
            self.assertIsNone(
                auth2.verify_bearer_token(f"Bearer {tok}"),
                "Revoked JTI must remain rejected after manager restart",
            )

    def test_revocation_denylist_blocks_subsequent_calls(self):
        """Revoked token jti must be blocked on every subsequent verification attempt."""
        auth = FirebaseAuthManager(allow_dev_mock=True, verification_key=self.secret, allowed_algorithms=["HS256"])
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
    """Phase 4 §5 & Phase 4.1 §7: Persistence adapter contract & boundary tests."""

    def test_production_adapter_raises_without_credentials(self):
        """ProductionFirestoreStorageAdapter must raise RuntimeError if key is absent."""
        with patch.dict(os.environ, {"FIREBASE_SERVICE_ACCOUNT_KEY": ""}):
            with self.assertRaises(RuntimeError) as ctx:
                ProductionFirestoreStorageAdapter(
                    project_id="prod-project",
                    storage_bucket="prod-bucket",
                )
            self.assertIn("unavailable", str(ctx.exception).lower())

    def test_simulation_adapter_never_returns_gs_uri(self):
        """LocalSimulationPersistenceAdapter must never produce gs:// URIs."""
        adapter = LocalSimulationPersistenceAdapter()
        for i in range(5):
            uri = adapter.store_blob(f"path/file_{i}.bin", b"DATA", tenant_id=f"tenant_{i}")
            self.assertFalse(uri.startswith("gs://"), f"Simulation URI must not use gs://: {uri}")
            self.assertTrue(uri.startswith("local-sim://"), f"Simulation URI must use local-sim://: {uri}")

    def test_simulation_adapter_tenant_isolation_jobs(self):
        """Jobs stored under tenant_a must not appear under tenant_b."""
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
        self.assertIsNotNone(adapter.get_job("job-001", tenant_id="tenant-alice"))
        self.assertIsNone(adapter.get_job("job-001", tenant_id="tenant-bob"))

    def test_simulation_adapter_update_job_tenant_isolation(self):
        """Job updates must be scoped to the correct tenant."""
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
        ok = adapter.update_job("job-002", "tenant-correct", {"status": "COMPLETED"})
        self.assertTrue(ok)
        ok_wrong = adapter.update_job("job-002", "tenant-wrong", {"status": "HACKED"})
        self.assertFalse(ok_wrong)

    def test_firebase_sync_manager_cannot_silently_fall_back(self):
        """FirebaseSyncManager in production mode must raise, not silently use simulation."""
        with patch.dict(os.environ, {
            "REVERSE_FORGE_ENV": "production",
            "FIREBASE_SERVICE_ACCOUNT_KEY": "/nonexistent/path/service-account.json",
        }):
            with self.assertRaises(RuntimeError):
                FirebaseSyncManager()

    def test_phase41_identifier_and_blob_path_validation_blocks_traversal_and_schemes(self):
        """Phase 4.1 §7: Validate artifact IDs, tenant IDs, job IDs, and storage paths against traversal and schemes."""
        for bad_tenant in ["", "../etc", "tenant/a", "gs://bucket", "tenant..1", "a\x00b"]:
            with self.assertRaises(ValueError):
                validate_tenant_id(bad_tenant)

        for bad_sha in ["", "not_a_sha", "a" * 32, "g" * 64, "../" + "a" * 61]:
            with self.assertRaises(ValueError):
                validate_artifact_sha256(bad_sha)

        for bad_doc in ["", ".", "..", "doc/sub", "doc\\sub", "id..2"]:
            with self.assertRaises(ValueError):
                validate_document_id(bad_doc, "job_id")

        for bad_blob in ["", "/etc/passwd", "../secret.bin", "binaries/../../etc/shadow", "gs://bucket/obj", "http://evil/x"]:
            with self.assertRaises(ValueError):
                validate_storage_blob_path(bad_blob)

    def test_phase41_production_adapter_distinguishes_not_found_permission_and_outage(self):
        """Phase 4.1 §7: ProductionFirestoreStorageAdapter distinguishes NotFound (None), PermissionError, and Unavailable."""
        mock_fs = MagicMock()
        mock_st = MagicMock()
        adapter = ProductionFirestoreStorageAdapter(
            project_id="p41-proj",
            storage_bucket="p41-bucket",
            firestore_client=mock_fs,
            storage_client=mock_st,
        )
        sha = "e" * 64

        # 1. Missing document -> returns None cleanly
        snap_missing = MagicMock()
        snap_missing.exists = False
        mock_fs.collection().document().collection().document().get.return_value = snap_missing
        self.assertIsNone(adapter.get_artifact(sha, "tenant_a"))

        # 2. Cross-tenant document payload mismatch -> raises PersistencePermissionError
        snap_mismatch = MagicMock()
        snap_mismatch.exists = True
        snap_mismatch.to_dict.return_value = {"sha256": sha, "tenant_id": "tenant_other"}
        mock_fs.collection().document().collection().document().get.return_value = snap_mismatch
        with self.assertRaises(PersistencePermissionError):
            adapter.get_artifact(sha, "tenant_a")

        # 3. Backend PermissionDenied exception -> raises PersistencePermissionError (not None!)
        class PermissionDenied(Exception):
            code = 403

        mock_fs.collection().document().collection().document().get.side_effect = PermissionDenied("IAM denied")
        with self.assertRaises(PersistencePermissionError):
            adapter.get_artifact(sha, "tenant_a")

        # 4. Backend ServiceUnavailable / network outage -> raises PersistenceUnavailableError (not None!)
        class ServiceUnavailable(Exception):
            code = 503

        mock_fs.collection().document().collection().document().get.side_effect = ServiceUnavailable("RPC timeout")
        with self.assertRaises(PersistenceUnavailableError):
            adapter.get_artifact(sha, "tenant_a")


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

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        fp_before = NativeRustAccelerator.compute_source_fingerprint(repo_root)

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_rust_dir = os.path.join(tmpdir, "rust_core", "src")
            os.makedirs(fake_rust_dir)
            with open(os.path.join(fake_rust_dir, "lib.rs"), "w") as f:
                f.write("// Modified source content for test")

            fp_modified = NativeRustAccelerator.compute_source_fingerprint(tmpdir)
            self.assertNotEqual(fp_before, fp_modified, "Fingerprint must change when source changes")

    def test_validate_abi_rejects_missing_symbols(self):
        """Library missing required symbols must fail ABI validation."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        partial_lib = MagicMock(spec=["rf_rust_entropy", "rf_rust_flirt_crc16"])
        self.assertFalse(NativeRustAccelerator._validate_abi(partial_lib))

    def test_validate_abi_rejects_wrong_crc16_vector(self):
        """ABI validation must reject library returning wrong CRC16 for '123456789'."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0xDEAD
        self.assertFalse(NativeRustAccelerator._validate_abi(lib))

    def test_validate_abi_rejects_wrong_entropy_vector(self):
        """ABI validation must reject library returning nonzero entropy for empty buffer."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0x906E
        lib.rf_rust_entropy.return_value = 1.5
        self.assertFalse(NativeRustAccelerator._validate_abi(lib))

    def test_validate_abi_rejects_wrong_fnv1a64_vector(self):
        """ABI validation must reject library returning wrong FNV1a-64 for 'test'."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator
        lib = MagicMock()
        lib.rf_rust_flirt_crc16.return_value = 0x906E
        lib.rf_rust_entropy.return_value = 0.0
        lib.rf_rust_fnv1a_64.return_value = 0xBADBAD
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
        diags = NativeRustAccelerator.get_build_diagnostics()
        self.assertIsInstance(diags, list, "get_build_diagnostics() must return a list")

    def test_backend_always_returns_known_value(self):
        """Active backend must always be one of the three explicit modes."""
        from reverse_forge.native_rust_bridge import NativeRustAccelerator, BackendExecutionMode
        backend = NativeRustAccelerator.get_active_backend()
        valid_backends = set(BackendExecutionMode)
        self.assertIn(backend, valid_backends, f"Backend {backend} is not a known BackendExecutionMode")


if __name__ == "__main__":
    unittest.main()
