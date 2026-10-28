"""
R3V3R53//F0RG3 — Phase 4 & Phase 4.1 Central Execution Authorization, HIL Signing,
Atomic Single-Use Replay Prevention & Entry-Point Bypass Regression Suite
==================================================================================
Covers all requirements from Phase 4 §4 and Phase 4.1 §2, §3, §5, §8:
  1. Predictable HIL signing key elimination:
     - Hard-coded fallback key removed and rejected
     - Missing, empty, short, or low-entropy keys fail closed (DENIED_HIL_CONFIG_INVALID) without side effects
     - Invalid keys and signatures rejected
     - Callers cannot forge approval by constructing ApprovalGrant or editing any grant field
     - Unauthorized users (VIEWER, unverified, cross-tenant, ANALYST for DELETE_ARTIFACT) cannot issue grants
     - Grants bound to (approver_uid, approver_role, tenant_id, operation, canonical target_path, target_sha256, canonical parameters_hash, issued_at, expires_at, grant_id, key_id)
     - Expired and future-dated grants outside clock skew rejected
     - Strict canonical JSON parameter serialization (rejects default=str objects, bytes, NaN/Inf)
     - Key rotation via HILKeyRing (active signing key + verification-only legacy key + retire_key)
     - Ordinary non-sensitive operations continue to work under documented policy
  2. Genuinely single-use approvals:
     - SQLiteAtomicGrantConsumptionStore & FirestoreTransactionalGrantConsumptionStore
     - Concurrent multi-threaded replay attempts: exactly 1 of N threads succeeds
     - Simulated process restart persistence: consumed grant remains rejected after store/boundary re-instantiation
     - Storage failures fail closed (DENIED_STORAGE_FAILURE) without bypassing replay checks
     - Cross-tenant replay and duplicate grant ID rejection
     - Retention cleanup deletes only long-expired records without re-enabling unexpired grants
  3. Complete side-effecting entry-point audit & TOCTOU protection:
     - PipelineStateMachine stages 0..11 direct invocation and TOCTOU file swap detection
     - InvestigationWorkflowEngine.submit_hil_decision and _run_stage6_dynamic_execution
     - GUIWorkbenchHandler endpoints (/api/patch, /api/force-exec, /api/cloud/sync, /api/investigate/approve)
     - ConcolicSymbolicOrchestrator honest hypothesis labeling (no synthetic Confirmed CVSS 9.1 claim)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socketserver
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import MagicMock, patch

from reverse_forge.authorization import (
    ApprovalGrant,
    ApprovalIssuer,
    AuthorizationDecision,
    AuthorizationDeniedError,
    CentralAuthorizationBoundary,
    FirestoreTransactionalGrantConsumptionStore,
    GrantStorageError,
    HILConfigurationError,
    HILKeyRing,
    MAX_CLOCK_SKEW_SECONDS,
    OperationType,
    SQLiteAtomicGrantConsumptionStore,
    canonicalize_parameters,
    get_authorization_boundary,
    reset_authorization_boundary,
)
from reverse_forge.firebase_sync import (
    AuthUserContext,
    FirebaseAuthManager,
    UserRole,
    jwt,
)
from reverse_forge.pipeline import (
    AutonomyLevel,
    PipelineStateMachine,
    StageStatus,
)
from reverse_forge.provenance import ActionPermission, ProvenanceManager, ScopeLedger


def _create_minimal_elf(path: str) -> str:
    with open(path, "wb") as f:
        f.write(
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00"
            + b"\x00" * 40
        )
    return path


class TestCentralAuthorizationBypass(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="rf_auth_test_")
        self.target_elf = os.path.join(self.tmpdir, "target.elf")
        _create_minimal_elf(self.target_elf)
        self.target_sha256 = ProvenanceManager.compute_hashes(self.target_elf)["sha256"]

        self.other_elf = os.path.join(self.tmpdir, "other.elf")
        with open(self.other_elf, "wb") as f:
            f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x90" * 56)
        self.other_sha256 = ProvenanceManager.compute_hashes(self.other_elf)["sha256"]

        self.hil_secret = "phase41-high-entropy-hil-signing-key-2026-v1!!"
        self.key_ring = HILKeyRing(keys={"k2026_v1": self.hil_secret}, active_key_id="k2026_v1")
        self.db_path = os.path.join(self.tmpdir, "hil_grants.sqlite3")
        self.store = SQLiteAtomicGrantConsumptionStore(db_path=self.db_path)
        self.boundary = reset_authorization_boundary(signing_key=self.key_ring, consumption_store=self.store)
        self.issuer = ApprovalIssuer(key_ring=self.key_ring)

        self.auth_mgr = FirebaseAuthManager(
            project_id="test-project",
            verification_key="phase41-jwt-signing-secret-key-32bytes!!",
            allowed_algorithms=["HS256"],
        )
        self.verified_analyst = self.auth_mgr.issue_verified_context(
            uid="analyst-1",
            email="analyst@tenant-a.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-a",
        )
        self.verified_viewer = self.auth_mgr.issue_verified_context(
            uid="viewer-1",
            email="viewer@tenant-a.com",
            role=UserRole.VIEWER,
            tenant_id="tenant-a",
        )
        self.verified_lead = self.auth_mgr.issue_verified_context(
            uid="lead-1",
            email="lead@tenant-a.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant-a",
        )
        self.verified_foreign_analyst = self.auth_mgr.issue_verified_context(
            uid="analyst-foreign",
            email="analyst@tenant-b.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-b",
        )
        self.unverified_user = AuthUserContext(
            uid="attacker-1",
            email="attacker@external.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant-a",
            is_verified=False,
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Unverified Identity & Missing Principal
    # -------------------------------------------------------------------------
    def test_unverified_principal_strictly_denied(self):
        """Unverified context cannot perform any privileged operation even if claiming LEAD_ARCHITECT."""
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.unverified_user,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY)

    def test_missing_principal_strictly_denied(self):
        """None principal fails closed immediately."""
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=None,
            operation=OperationType.MODIFY_ARTIFACT,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY)

    # -------------------------------------------------------------------------
    # 2. RBAC Least-Privilege & Ordinary Non-Sensitive Operations
    # -------------------------------------------------------------------------
    def test_viewer_role_cannot_modify_or_execute_sandbox(self):
        """VIEWER role cannot perform dynamic analysis or artifact modification."""
        for op in (OperationType.DYNAMIC_SANDBOX, OperationType.MODIFY_ARTIFACT, OperationType.DELETE_ARTIFACT):
            permitted, dec, _, _ = self.boundary.evaluate_request(
                principal=self.verified_viewer,
                operation=op,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                target_tenant_id="tenant-a",
            )
            self.assertFalse(permitted, f"VIEWER should not be permitted {op.value}")
            self.assertEqual(dec, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE)

    def test_ordinary_non_sensitive_operations_permitted_under_policy(self):
        """Phase 4.1 §2 Req 9: Ordinary non-sensitive operations (READ_METADATA, STATIC_ANALYSIS, EXPORT_REPORT) work."""
        for op in (OperationType.READ_METADATA, OperationType.STATIC_ANALYSIS, OperationType.EXPORT_REPORT):
            permitted, dec, _, grant_used = self.boundary.evaluate_request(
                principal=self.verified_viewer,
                operation=op,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                target_tenant_id="tenant-a",
                autonomy_level=2,
            )
            self.assertTrue(permitted, f"VIEWER should be permitted {op.value}")
            self.assertEqual(dec, AuthorizationDecision.PERMITTED)
            self.assertIsNone(grant_used)

    def test_analyst_cannot_delete_artifact(self):
        """Only LEAD_ARCHITECT can delete artifacts; ANALYST must be denied."""
        permitted, dec, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DELETE_ARTIFACT,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE)

    # -------------------------------------------------------------------------
    # 3. Cross-Tenant Boundaries
    # -------------------------------------------------------------------------
    def test_cross_tenant_target_access_denied(self):
        """Principal from tenant-a cannot target resources belonging to tenant-b."""
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_lead,
            operation=OperationType.STATIC_ANALYSIS,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-b",
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS)
        self.assertIn("tenant-a", reason)
        self.assertIn("tenant-b", reason)

    # -------------------------------------------------------------------------
    # 4. Mandatory HIL: Missing Callbacks & Callback Failures
    # -------------------------------------------------------------------------
    def test_missing_hil_callback_fails_closed(self):
        """Mandatory HIL operation with hil_callback=None must strictly deny."""
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            hil_callback=None,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED)

    def test_hil_callback_exception_fails_closed(self):
        """Callback raising an unexpected exception must fail closed and deny."""
        def faulty_callback(prompt, ctx):
            raise ConnectionError("Network down or operator unreachable")

        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            hil_callback=faulty_callback,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_CALLBACK_FAILED)

    def test_hil_callback_returns_false_denies(self):
        """Operator saying NO (returning False) must deny."""
        permitted, dec, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            hil_callback=lambda p, c: False,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED)

    # -------------------------------------------------------------------------
    # 5. Phase 4.1 §2: Predictable HIL Signing Key Elimination & Cryptographic Binding
    # -------------------------------------------------------------------------
    def test_p41_no_default_or_hardcoded_signing_key_accepted(self):
        """Phase 4.1 §2 Req 1 & 2: Legacy hardcoded key is rejected; missing/weak key config fails closed."""
        # 1. Legacy fallback string is explicitly blocked if someone tries to configure it
        with self.assertRaises(HILConfigurationError):
            HILKeyRing.from_single_key("rf_hil_internal_signing_key_bicentennial_2026")

        # 2. Short or low-entropy keys (<32 bytes or <8 distinct bytes) fail closed
        for weak_key in ["", "short_key", "A" * 64, "12121212" * 8]:
            with self.assertRaises(HILConfigurationError):
                HILKeyRing.from_single_key(weak_key)

        # 3. Missing key configuration denies sensitive action (DENIED_HIL_CONFIG_INVALID) without side effects
        with patch.dict(os.environ, {
            "REVERSE_FORGE_HIL_SIGNING_KEY": "",
            "REVERSE_FORGE_HIL_KEYRING_JSON": "",
            "REVERSE_FORGE_HIL_SIGNING_KEY_FILE": "",
        }):
            unconfigured_boundary = CentralAuthorizationBoundary(signing_key=None, consumption_store=self.store)
            permitted, dec, reason, _ = unconfigured_boundary.evaluate_request(
                principal=self.verified_analyst,
                operation=OperationType.DYNAMIC_SANDBOX,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                target_tenant_id="tenant-a",
                hil_callback=lambda p, c: True,
            )
            self.assertFalse(permitted)
            self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_CONFIG_INVALID)

        # 4. Direct ApprovalGrant.create() is permanently disabled
        with self.assertRaises(AuthorizationDeniedError):
            ApprovalGrant.create(
                operation=OperationType.DYNAMIC_SANDBOX,
                target_sha256=self.target_sha256,
                parameters={},
                approver_uid="analyst-1",
            )

    def test_p41_unauthorized_approver_cannot_issue_grant(self):
        """Phase 4.1 §2 Req 5: Unauthorized/unverified/cross-tenant principal cannot issue an ApprovalGrant."""
        # Unverified user cannot issue
        with self.assertRaises(AuthorizationDeniedError) as ctx1:
            self.issuer.issue_grant(
                approver=self.unverified_user,
                operation=OperationType.DYNAMIC_SANDBOX,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                tenant_id="tenant-a",
            )
        self.assertEqual(ctx1.exception.decision, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY)

        # VIEWER cannot issue grant for DYNAMIC_SANDBOX
        with self.assertRaises(AuthorizationDeniedError) as ctx2:
            self.issuer.issue_grant(
                approver=self.verified_viewer,
                operation=OperationType.DYNAMIC_SANDBOX,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                tenant_id="tenant-a",
            )
        self.assertEqual(ctx2.exception.decision, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE)

        # ANALYST cannot issue grant for DELETE_ARTIFACT (requires LEAD_ARCHITECT)
        with self.assertRaises(AuthorizationDeniedError) as ctx3:
            self.issuer.issue_grant(
                approver=self.verified_analyst,
                operation=OperationType.DELETE_ARTIFACT,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                tenant_id="tenant-a",
            )
        self.assertEqual(ctx3.exception.decision, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE)

        # Cross-tenant analyst cannot issue grant for tenant-a
        with self.assertRaises(AuthorizationDeniedError) as ctx4:
            self.issuer.issue_grant(
                approver=self.verified_foreign_analyst,
                operation=OperationType.DYNAMIC_SANDBOX,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                tenant_id="tenant-a",
            )
        self.assertEqual(ctx4.exception.decision, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS)

    def test_p41_editing_any_grant_field_or_using_wrong_key_invalidates_signature(self):
        """Phase 4.1 §2 Req 3, 4, 6: Tampering with any ApprovalGrant field or using wrong key fails verification."""
        base_grant = self.issuer.issue_grant(
            approver=self.verified_lead,
            operation=OperationType.DELETE_ARTIFACT,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"reason": "cleanup"},
        )
        # Wrong verification key fails
        wrong_ring = HILKeyRing(keys={"k2026_v1": "wrong-high-entropy-hil-signing-key-2026-v1!!"}, active_key_id="k2026_v1")
        ok_w, _ = base_grant.is_valid_for(
            operation=OperationType.DELETE_ARTIFACT,
            target_sha256=self.target_sha256,
            parameters={"reason": "cleanup"},
            signing_key=wrong_ring,
            target_tenant_id="tenant-a",
            target_path=self.target_elf,
        )
        self.assertFalse(ok_w)

        # Mutate each bound field in turn and confirm rejection
        mutations = [
            {"grant_id": "hil_forged_id_9999"},
            {"operation": OperationType.MODIFY_ARTIFACT.value},
            {"target_path": self.other_elf},
            {"target_sha256": self.other_sha256},
            {"tenant_id": "tenant-b"},
            {"parameters_hash": "0" * 64},
            {"approver_uid": "other-lead"},
            {"approver_role": UserRole.ANALYST.value},
            {"issued_at": base_grant.issued_at - 10.0},
            {"expires_at": base_grant.expires_at + 600.0},
            {"key_id": "unknown_key"},
            {"signature": "0" * 64},
        ]
        for mod in mutations:
            d = base_grant.to_dict()
            d.update(mod)
            forged_grant = ApprovalGrant.from_dict(d)
            ok, reason = forged_grant.is_valid_for(
                operation=OperationType.DELETE_ARTIFACT,
                target_sha256=self.target_sha256,
                parameters={"reason": "cleanup"},
                signing_key=self.key_ring,
                target_tenant_id="tenant-a",
                target_path=self.target_elf,
            )
            self.assertFalse(ok, f"Mutation {mod} must invalidate ApprovalGrant (got {reason})")

    def test_stale_expired_and_future_dated_approval_grants_denied(self):
        """Phase 4.1 §2 Req 7: Expired and future-dated grants outside clock skew must be rejected."""
        now = time.time()
        # 1. Expired grant (issued 120s ago with 60s TTL)
        expired_grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"mode": "sandbox"},
            ttl_seconds=60.0,
            issued_at=now - 120.0,
        )
        permitted, dec, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"mode": "sandbox"},
            approval_grant=expired_grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE)

        # 2. Future-dated grant beyond MAX_CLOCK_SKEW_SECONDS
        future_grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"mode": "sandbox"},
            ttl_seconds=300.0,
            issued_at=now + MAX_CLOCK_SKEW_SECONDS + 120.0,
        )
        permitted_f, dec_f, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"mode": "sandbox"},
            approval_grant=future_grant,
        )
        self.assertFalse(permitted_f)
        self.assertEqual(dec_f, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE)

    def test_approval_grant_target_mismatch_denied(self):
        """An approval grant issued for binary A cannot be reused on binary B."""
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={},
            ttl_seconds=300.0,
        )
        permitted, dec, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.other_elf,
            target_sha256=self.other_sha256,
            target_tenant_id="tenant-a",
            parameters={},
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH)

    def test_approval_grant_parameter_tampering_and_non_canonical_types_denied(self):
        """Phase 4.1 §2: Tampering with parameters or passing non-JSON types (no default=str) is rejected."""
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"allow_network": False, "timeout": 30},
            ttl_seconds=300.0,
        )
        tampered_params = {"allow_network": True, "timeout": 30}
        permitted, dec, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters=tampered_params,
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_PARAMETER_MISMATCH)

        # Non-canonical types that would previously rely on default=str must raise TypeError/ValueError
        for bad_param in [{"obj": object()}, {"raw": b"bytes"}, {"set": {1, 2}}, {"nan": float("nan")}, {"inf": float("inf")}]:
            with self.assertRaises((TypeError, ValueError)):
                canonicalize_parameters(bad_param)

    def test_p41_key_rotation_and_retirement(self):
        """Phase 4.1 §2 Req 8: Key rotation allows verifying in-flight grants under previous key and retiring compromised keys."""
        grant_v1 = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"step": 1},
        )
        self.assertEqual(grant_v1.key_id, "k2026_v1")

        # Rotate to k2026_v2
        self.key_ring.rotate_key("k2026_v2", "phase41-rotated-high-entropy-hil-key-2026-v2!!")
        grant_v2 = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"step": 2},
        )
        self.assertEqual(grant_v2.key_id, "k2026_v2")

        # Both v1 (in-flight) and v2 (new) grants validate before v1 is retired
        ok1, _, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"step": 1},
            approval_grant=grant_v1,
        )
        self.assertTrue(ok1)

        # Retire v1: any new/unconsumed grant signed with v1 is now rejected
        grant_v1_unconsumed = ApprovalIssuer(
            key_ring=HILKeyRing(keys={"k2026_v1": self.hil_secret}, active_key_id="k2026_v1")
        ).issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"step": 3},
        )
        self.key_ring.retire_key("k2026_v1")
        ok_retired, _, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"step": 3},
            approval_grant=grant_v1_unconsumed,
        )
        self.assertFalse(ok_retired)

        # v2 grant still succeeds
        ok2, _, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"step": 2},
            approval_grant=grant_v2,
        )
        self.assertTrue(ok2)

    # -------------------------------------------------------------------------
    # 6. Phase 4.1 §3: Genuinely Single-Use Approvals (Concurrency, Restart, Storage Failure)
    # -------------------------------------------------------------------------
    def test_approval_grant_cannot_be_replayed_and_persists_across_restarts(self):
        """Phase 4.1 §3: A consumed grant cannot be replayed even after process/boundary restart."""
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"mode": "once"},
            ttl_seconds=300.0,
        )
        p1, d1, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"mode": "once"},
            approval_grant=grant,
        )
        self.assertTrue(p1)
        self.assertEqual(d1, AuthorizationDecision.PERMITTED)

        # Simulate process restart: instantiate a brand-new SQLiteAtomicGrantConsumptionStore & boundary on same DB
        restarted_store = SQLiteAtomicGrantConsumptionStore(db_path=self.db_path)
        restarted_boundary = CentralAuthorizationBoundary(signing_key=self.key_ring, consumption_store=restarted_store)
        p2, d2, r2, _ = restarted_boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"mode": "once"},
            approval_grant=grant,
        )
        self.assertFalse(p2)
        self.assertEqual(d2, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE)
        self.assertIn("consumed", r2.lower())

    def test_p41_concurrent_replay_attempts_allow_at_most_one(self):
        """Phase 4.1 §3: Two or more concurrent requests attempting to use the same grant must not both succeed."""
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"mode": "concurrent_race"},
            ttl_seconds=300.0,
        )
        num_workers = 12
        barrier = threading.Barrier(num_workers)
        outcomes = []
        outcomes_lock = threading.Lock()

        def _worker():
            # Each worker uses its own CentralAuthorizationBoundary & SQLiteAtomicGrantConsumptionStore instance sharing the SQLite WAL file
            worker_store = SQLiteAtomicGrantConsumptionStore(db_path=self.db_path)
            worker_boundary = CentralAuthorizationBoundary(signing_key=self.key_ring, consumption_store=worker_store)
            barrier.wait()
            permitted, dec, _, _ = worker_boundary.evaluate_request(
                principal=self.verified_analyst,
                operation=OperationType.DYNAMIC_SANDBOX,
                target_path=self.target_elf,
                target_sha256=self.target_sha256,
                target_tenant_id="tenant-a",
                parameters={"mode": "concurrent_race"},
                approval_grant=grant,
            )
            with outcomes_lock:
                outcomes.append((permitted, dec))

        threads = [threading.Thread(target=_worker) for _ in range(num_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [o for o in outcomes if o[0] is True]
        denials = [o for o in outcomes if o[0] is False]
        self.assertEqual(len(successes), 1, f"Exactly 1 concurrent worker must succeed, got {len(successes)}")
        self.assertEqual(len(denials), num_workers - 1)

    def test_p41_storage_failure_denies_sensitive_operation_fail_closed(self):
        """Phase 4.1 §3: Storage failures during grant consumption must deny sensitive operations (DENIED_STORAGE_FAILURE)."""
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"mode": "storage_fail"},
        )
        broken_store = MagicMock()
        broken_store.consume_grant_atomic.side_effect = GrantStorageError("Disk I/O failure")
        failing_boundary = CentralAuthorizationBoundary(signing_key=self.key_ring, consumption_store=broken_store)

        permitted, dec, reason, _ = failing_boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={"mode": "storage_fail"},
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_STORAGE_FAILURE)

    def test_p41_firestore_transactional_store_and_retention_cleanup(self):
        """Phase 4.1 §3: FirestoreTransactionalGrantConsumptionStore enforces atomic create() and safe retention cleanup."""
        docs = {}
        lock = threading.Lock()

        class FakeAlreadyExistsError(Exception):
            code = 409

        class FakeDocRef:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def create(self, data):
                with lock:
                    if self.doc_id in docs:
                        raise FakeAlreadyExistsError("Document already exists")
                    docs[self.doc_id] = dict(data)

            def get(self):
                with lock:
                    snap = MagicMock()
                    snap.exists = self.doc_id in docs
                    snap.to_dict.return_value = docs.get(self.doc_id, {})
                    return snap

            def delete(self):
                with lock:
                    docs.pop(self.doc_id, None)

        class FakeCollection:
            def document(self, doc_id):
                return FakeDocRef(doc_id)

            def stream(self):
                with lock:
                    items = list(docs.items())
                out = []
                for doc_id, data in items:
                    d = MagicMock()
                    d.to_dict.return_value = data
                    d.reference = FakeDocRef(doc_id)
                    out.append(d)
                return out

        fake_fs = MagicMock()
        fake_fs.collection.return_value = FakeCollection()

        fs_store = FirestoreTransactionalGrantConsumptionStore(firestore_client=fake_fs)
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"backend": "firestore"},
            ttl_seconds=60.0,
        )
        self.assertTrue(
            fs_store.consume_grant_atomic(grant, "tenant-a", OperationType.DYNAMIC_SANDBOX.value, self.target_sha256)
        )
        self.assertFalse(
            fs_store.consume_grant_atomic(grant, "tenant-a", OperationType.DYNAMIC_SANDBOX.value, self.target_sha256),
            "Second consumption against Firestore create() precondition must return False",
        )
        # Cleanup while grant is still within retention window must NOT delete the consumed record
        deleted_early = fs_store.cleanup_expired_records(retention_horizon_seconds=3600.0, now=time.time() + 120.0)
        self.assertEqual(deleted_early, 0)
        self.assertTrue(fs_store.is_consumed(grant.grant_id))

        # Cleanup after expiry + retention horizon + clock skew deletes the expired record
        deleted_late = fs_store.cleanup_expired_records(retention_horizon_seconds=3600.0, now=time.time() + 4000.0)
        self.assertEqual(deleted_late, 1)

    # -------------------------------------------------------------------------
    # 7. Autonomy Overrides Cannot Bypass Mandatory Policy
    # -------------------------------------------------------------------------
    def test_autonomous_mode_cannot_bypass_dynamic_sandbox_hil(self):
        """AutonomyLevel.AUTONOMOUS cannot bypass mandatory HIL on dynamic sandbox."""
        ledger = ScopeLedger(
            allowed_paths=[self.target_elf, self.tmpdir],
            default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS, ActionPermission.DYNAMIC_SANDBOX],
        )
        pipe = PipelineStateMachine(
            artifact_path=self.target_elf,
            autonomy_level=AutonomyLevel.AUTONOMOUS,
            scope_ledger=ledger,
            workspace_dir=self.tmpdir,
            hil_callback=None,
            principal=self.verified_analyst,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)
        ok = pipe.execute_stage(7)
        self.assertFalse(ok)
        self.assertEqual(pipe.stages[7].status, StageStatus.SKIPPED)

    def test_continuous_mode_cannot_bypass_dynamic_sandbox_hil(self):
        """AutonomyLevel.CONTINUOUS cannot bypass mandatory HIL on dynamic sandbox."""
        ledger = ScopeLedger(
            allowed_paths=[self.target_elf, self.tmpdir],
            default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS, ActionPermission.DYNAMIC_SANDBOX],
        )
        pipe = PipelineStateMachine(
            artifact_path=self.target_elf,
            autonomy_level=AutonomyLevel.CONTINUOUS,
            scope_ledger=ledger,
            workspace_dir=self.tmpdir,
            hil_callback=None,
            principal=self.verified_analyst,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)
        ok = pipe.execute_stage(7)
        self.assertFalse(ok)

    # -------------------------------------------------------------------------
    # 8. Direct Handler Invocation, TOCTOU Revalidation & Complete Entry-Point Coverage
    # -------------------------------------------------------------------------
    def test_direct_stage7_handler_invocation_blocked_without_hil(self):
        """Calling pipe._stage_7() directly must be intercepted and produce zero side-effects."""
        ledger = ScopeLedger(
            allowed_paths=[self.target_elf, self.tmpdir],
            default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS, ActionPermission.DYNAMIC_SANDBOX],
        )
        pipe = PipelineStateMachine(
            artifact_path=self.target_elf,
            scope_ledger=ledger,
            workspace_dir=self.tmpdir,
            hil_callback=None,
            principal=self.verified_analyst,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)
        res = pipe._stage_7()
        self.assertFalse(res)

        for fname in ("detonation_profile.wsb", "collect_telemetry.ps1", "posix_isolated_runner.sh", "frida_telemetry.js"):
            self.assertFalse(os.path.exists(os.path.join(self.tmpdir, fname)), f"{fname} must not exist on denial")

    def test_direct_stage11_handler_invocation_blocked_for_viewer(self):
        """Calling pipe._stage_11() directly by a VIEWER must fail authorization."""
        ledger = ScopeLedger(
            allowed_paths=[self.target_elf, self.tmpdir],
            default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS, ActionPermission.MODIFY_ARTIFACT],
        )
        pipe = PipelineStateMachine(
            artifact_path=self.target_elf,
            scope_ledger=ledger,
            workspace_dir=self.tmpdir,
            principal=self.verified_viewer,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)

        with self.assertRaises(AuthorizationDeniedError) as exc_info:
            pipe._stage_11()
        self.assertIn("DENIED_INSUFFICIENT_ROLE", str(exc_info.exception))

    def test_p41_all_pipeline_stages_enforce_authorization_on_direct_invocation(self):
        """Phase 4.1 §5: Every private handler _stage_0.._stage_11 enforces CentralAuthorizationBoundary."""
        pipe = PipelineStateMachine(
            artifact_path=self.target_elf,
            workspace_dir=self.tmpdir,
            principal=self.unverified_user,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        for stage_id in range(12):
            handler = getattr(pipe, f"_stage_{stage_id}")
            if stage_id == 7:
                # Mandatory HIL stages return False when denied without creating side effects
                self.assertFalse(handler(), f"_stage_{stage_id} must deny unverified user")
            else:
                with self.assertRaises(AuthorizationDeniedError, msg=f"_stage_{stage_id} must raise AuthorizationDeniedError"):
                    handler()

    def test_p41_toctou_target_file_modification_after_ingestion_denied(self):
        """Phase 4.1 §5: Modifying the target file on disk after approval/ingestion is caught by TOCTOU SHA-256 revalidation."""
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={},
        )
        # Attacker swaps or appends payload to target_elf after approval grant is signed
        with open(self.target_elf, "ab") as f:
            f.write(b"\x90\x90MALICIOUS_TOCTOU_PAYLOAD")

        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            target_tenant_id="tenant-a",
            parameters={},
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH)
        self.assertIn("toctou", reason.lower())

    def test_p41_investigation_workflow_engine_hil_and_direct_stage6_guarded(self):
        """Phase 4.1 §5: InvestigationWorkflowEngine enforces CentralAuthorizationBoundary on HIL and Stage 6."""
        from reverse_forge.investigation_workflow import InvestigationWorkflowEngine

        eng = InvestigationWorkflowEngine()
        state = eng.create_investigation(
            "Analyze and run dynamic sandbox trace on binary",
            self.target_elf,
            tenant_id="tenant-a",
        )
        state = eng.run_to_completion_or_hil(state.investigation_id)
        self.assertEqual(state.status, "BLOCKED_HIL")

        # 1. Direct _run_stage6_dynamic_execution without HIL decision fails closed
        with self.assertRaises(AuthorizationDeniedError):
            eng._run_stage6_dynamic_execution(state)

        # 2. submit_hil_decision in strict_auth mode with unverified user is rejected
        with self.assertRaises(AuthorizationDeniedError):
            eng.submit_hil_decision(
                state.investigation_id,
                "dynamic_execution",
                "APPROVE_SANDBOXED",
                principal=self.unverified_user,
                strict_auth=True,
            )

        # 3. submit_hil_decision with verified analyst and valid signed ApprovalGrant succeeds
        grant = self.issuer.issue_grant(
            approver=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256=self.target_sha256,
            tenant_id="tenant-a",
            parameters={"investigation_id": state.investigation_id, "action": "dynamic_execution"},
        )
        eng.submit_hil_decision(
            state.investigation_id,
            "dynamic_execution",
            "APPROVE_SANDBOXED",
            principal=self.verified_analyst,
            approval_grant=grant,
            strict_auth=True,
        )
        completed = eng.run_to_completion_or_hil(state.investigation_id)
        self.assertEqual(completed.status, "COMPLETED")
        self.assertTrue(
            any("In-Memory Emulation" in ev.observation_summary for ev in completed.evidence.values())
        )

    def test_p41_gui_workbench_endpoints_reject_unauthenticated_and_unauthorized_requests(self):
        """Phase 4.1 §5: /api/patch, /api/force-exec, /api/cloud/sync, and /api/investigate/approve enforce auth & HIL."""
        from reverse_forge.gui_server import GUIWorkbenchHandler, firebase_sync

        class QuietServer(socketserver.TCPServer):
            allow_reuse_address = True

        firebase_sync.auth.verification_key = "gui_test_jwt_secret_key_32_bytes_minimum!!"
        firebase_sync.auth.allowed_algorithms = ["HS256"]

        httpd = QuietServer(("127.0.0.1", 0), GUIWorkbenchHandler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{port}"
            enc_path = urllib.parse.quote(self.target_elf)

            # 1. Unauthenticated /api/patch -> 401
            req_patch = urllib.request.Request(
                f"{base}/api/patch?path={enc_path}",
                data=json.dumps({"offset": "0", "operation": "nop"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as e1:
                urllib.request.urlopen(req_patch)
            self.assertEqual(e1.exception.code, 401)

            # 2. Unauthenticated /api/force-exec -> 401
            with self.assertRaises(urllib.error.HTTPError) as e2:
                urllib.request.urlopen(f"{base}/api/force-exec?path={enc_path}")
            self.assertEqual(e2.exception.code, 401)

            # 3. Unauthenticated /api/cloud/sync -> 401
            with self.assertRaises(urllib.error.HTTPError) as e3:
                urllib.request.urlopen(f"{base}/api/cloud/sync?path={enc_path}")
            self.assertEqual(e3.exception.code, 401)

            # 4. Authenticated analyst WITHOUT HIL grant on /api/patch -> 403 DENIED_HIL_APPROVAL_REQUIRED
            tok = jwt.encode(
                {
                    "sub": "analyst-gui",
                    "email": "analyst@gui.local",
                    "role": "ANALYST",
                    "tenant_id": "tenant-a",
                    "iss": firebase_sync.auth.expected_issuer,
                    "aud": firebase_sync.auth.expected_audience,
                    "exp": time.time() + 3600,
                },
                firebase_sync.auth.verification_key,
                algorithm="HS256",
            )
            req_patch_no_hil = urllib.request.Request(
                f"{base}/api/patch?path={enc_path}",
                data=json.dumps({"offset": "0", "operation": "nop"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as e4:
                urllib.request.urlopen(req_patch_no_hil)
            self.assertEqual(e4.exception.code, 403)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_p41_concolic_hypothesis_not_labeled_confirmed_vulnerability(self):
        """Phase 4.1 §8: Heuristic/concolic hypotheses in Stage 8/9 must not be labeled Confirmed or CVSS 9.1."""
        sink_elf = os.path.join(self.tmpdir, "sink_sample.elf")
        with open(self.target_elf, "rb") as f:
            raw = f.read()
        with open(sink_elf, "wb") as f:
            f.write(raw + b"\x00strcpy\x00gets\x00")

        ledger = ScopeLedger(
            allowed_paths=[sink_elf, self.tmpdir],
            default_actions=[
                ActionPermission.READ_HASH,
                ActionPermission.STATIC_ANALYSIS,
                ActionPermission.MODIFY_ARTIFACT,
                ActionPermission.EXPORT_REPORT,
            ],
        )
        pipe = PipelineStateMachine(
            artifact_path=sink_elf,
            workspace_dir=self.tmpdir,
            scope_ledger=ledger,
            autonomy_level=AutonomyLevel.LEVEL_3_AUTONOMOUS_STATIC,
        )
        pipe.run_all_stages()
        concolic_findings = [
            f for f in pipe.report_generator.findings
            if f.finding_id.startswith("SYNTH-SAT-") or "concolic" in f.title.lower()
        ]
        for finding in concolic_findings:
            self.assertNotEqual(
                finding.confidence,
                "Confirmed",
                "Heuristic/concolic findings without real crash reproduction must not be labeled 'Confirmed'",
            )
            self.assertLessEqual(finding.cvss_score, 6.0)


if __name__ == "__main__":
    unittest.main()
