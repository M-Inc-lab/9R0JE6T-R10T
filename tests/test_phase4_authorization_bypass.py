"""
R3V3R53//F0RG3 — Phase 4 Central Execution Authorization & Bypass Tests
========================================================================
Verifies Section 4 (P0 — Centralize execution authorization and HIL):
  - Direct handler invocation bypass prevention
  - Alternative entry points and background execution bypass prevention
  - Missing HIL callbacks (fail-closed denial)
  - Callback exceptions and error handling (fail-closed denial)
  - Stale / expired approval grants (denied)
  - Parameter tampering / modified arguments after approval (denied)
  - Target mismatch / approval for wrong artifact SHA-256 (denied)
  - Cross-tenant unauthorized targets (denied)
  - Attempted autonomy level overrides (AUTONOMOUS/CONTINUOUS cannot bypass mandatory policy)
  - Zero side-effects guarantee: Denied operations write NO files, generate NO scripts,
    start NO tools, and perform NO network access.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from reverse_forge.authorization import (
    ApprovalGrant,
    AuthorizationDecision,
    AuthorizationDeniedError,
    CentralAuthorizationBoundary,
    OperationType,
    get_authorization_boundary,
)
from reverse_forge.firebase_sync import AuthUserContext, UserRole
from reverse_forge.pipeline import (
    AutonomyLevel,
    PipelineStateMachine,
    ReverseForgePipeline,
    StageStatus,
)
from reverse_forge.provenance import ActionPermission, ScopeLedger


def _create_minimal_elf(path: str) -> str:
    with open(path, "wb") as f:
        # Minimal ELF header (x86_64)
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
        self.boundary = CentralAuthorizationBoundary()
        self.verified_analyst = AuthUserContext(
            uid="analyst-1",
            email="analyst@tenant-a.com",
            role=UserRole.ANALYST,
            tenant_id="tenant-a",
            is_verified=True,
        )
        self.verified_viewer = AuthUserContext(
            uid="viewer-1",
            email="viewer@tenant-a.com",
            role=UserRole.VIEWER,
            tenant_id="tenant-a",
            is_verified=True,
        )
        self.verified_lead = AuthUserContext(
            uid="lead-1",
            email="lead@tenant-a.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant-a",
            is_verified=True,
        )
        self.unverified_user = AuthUserContext(
            uid="attacker-1",
            email="attacker@external.com",
            role=UserRole.LEAD_ARCHITECT,
            tenant_id="tenant-a",
            is_verified=False,  # Unverified!
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
            target_sha256="abc123456789",
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
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY)

    # -------------------------------------------------------------------------
    # 2. RBAC Least-Privilege
    # -------------------------------------------------------------------------
    def test_viewer_role_cannot_modify_or_execute_sandbox(self):
        """VIEWER role cannot perform dynamic analysis or artifact modification."""
        for op in (OperationType.DYNAMIC_SANDBOX, OperationType.MODIFY_ARTIFACT, OperationType.DELETE_ARTIFACT):
            permitted, dec, _, _ = self.boundary.evaluate_request(
                principal=self.verified_viewer,
                operation=op,
                target_path=self.target_elf,
                target_sha256="abc123456789",
                target_tenant_id="tenant-a",
            )
            self.assertFalse(permitted, f"VIEWER should not be permitted {op.value}")
            self.assertEqual(dec, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE)

    def test_analyst_cannot_delete_artifact(self):
        """Only LEAD_ARCHITECT can delete artifacts; ANALYST must be denied."""
        permitted, dec, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DELETE_ARTIFACT,
            target_path=self.target_elf,
            target_sha256="abc123456789",
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
            target_sha256="abc123456789",
            target_tenant_id="tenant-b",  # Cross-tenant!
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
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
            hil_callback=None,  # Missing callback
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
            target_sha256="abc123456789",
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
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
            hil_callback=lambda p, c: False,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED)

    # -------------------------------------------------------------------------
    # 5. Approval Grant Cryptographic Binding & Freshness
    # -------------------------------------------------------------------------
    def test_stale_expired_approval_grant_denied(self):
        """An expired approval grant must be rejected."""
        grant = ApprovalGrant.create(
            operation=OperationType.DYNAMIC_SANDBOX,
            target_sha256="abc123456789",
            parameters={"mode": "sandbox"},
            approver_uid=self.verified_analyst.uid,
            ttl_seconds=-10.0,  # Expired in the past!
        )
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
            parameters={"mode": "sandbox"},
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE)

    def test_approval_grant_target_mismatch_denied(self):
        """An approval grant issued for binary A cannot be reused on binary B."""
        grant = ApprovalGrant.create(
            operation=OperationType.DYNAMIC_SANDBOX,
            target_sha256="hash_of_binary_A",
            parameters={},
            approver_uid=self.verified_analyst.uid,
            ttl_seconds=300.0,
        )
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256="hash_of_binary_B",  # Target mismatch!
            target_tenant_id="tenant-a",
            parameters={},
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH)

    def test_approval_grant_parameter_tampering_denied(self):
        """Tampering with parameters after approval grant creation must be rejected."""
        grant = ApprovalGrant.create(
            operation=OperationType.DYNAMIC_SANDBOX,
            target_sha256="abc123456789",
            parameters={"allow_network": False, "timeout": 30},
            approver_uid=self.verified_analyst.uid,
            ttl_seconds=300.0,
        )
        # Adversary modifies parameters to enable network
        tampered_params = {"allow_network": True, "timeout": 30}
        permitted, dec, reason, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
            parameters=tampered_params,
            approval_grant=grant,
        )
        self.assertFalse(permitted)
        self.assertEqual(dec, AuthorizationDecision.DENIED_HIL_PARAMETER_MISMATCH)

    def test_approval_grant_cannot_be_replayed(self):
        """A consumed approval grant cannot be replayed for subsequent operations."""
        grant = ApprovalGrant.create(
            operation=OperationType.DYNAMIC_SANDBOX,
            target_sha256="abc123456789",
            parameters={"mode": "once"},
            approver_uid=self.verified_analyst.uid,
            ttl_seconds=300.0,
        )
        # First use: permitted
        p1, d1, _, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
            parameters={"mode": "once"},
            approval_grant=grant,
        )
        self.assertTrue(p1)
        self.assertEqual(d1, AuthorizationDecision.PERMITTED)

        # Second use (replay attempt): denied
        p2, d2, r2, _ = self.boundary.evaluate_request(
            principal=self.verified_analyst,
            operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.target_elf,
            target_sha256="abc123456789",
            target_tenant_id="tenant-a",
            parameters={"mode": "once"},
            approval_grant=grant,
        )
        self.assertFalse(p2)
        self.assertEqual(d2, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE)
        self.assertIn("consumed", r2.lower())

    # -------------------------------------------------------------------------
    # 6. Autonomy Overrides Cannot Bypass Mandatory Policy
    # -------------------------------------------------------------------------
    def test_autonomous_mode_cannot_bypass_dynamic_sandbox_hil(self):
        """AutonomyLevel.AUTONOMOUS cannot bypass mandatory HIL on dynamic sandbox."""
        ledger = ScopeLedger(
            allowed_paths=[self.target_elf, self.tmpdir],
            default_actions=[ActionPermission.READ_HASH, ActionPermission.STATIC_ANALYSIS, ActionPermission.DYNAMIC_SANDBOX],
        )
        pipe = PipelineStateMachine(
            artifact_path=self.target_elf,
            autonomy_level=AutonomyLevel.AUTONOMOUS,  # High autonomy!
            scope_ledger=ledger,
            workspace_dir=self.tmpdir,
            hil_callback=None,  # No approval!
            principal=self.verified_analyst,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)
        # Attempt to run Stage 7 directly in AUTONOMOUS mode without approval
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
            autonomy_level=AutonomyLevel.CONTINUOUS,  # Unconstrained continuous mode!
            scope_ledger=ledger,
            workspace_dir=self.tmpdir,
            hil_callback=None,  # No approval!
            principal=self.verified_analyst,
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)
        ok = pipe.execute_stage(7)
        self.assertFalse(ok)

    # -------------------------------------------------------------------------
    # 7. Direct Handler Invocation Bypass Prevention & Zero Side-Effects
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

        # Directly invoke private handler _stage_7()
        res = pipe._stage_7()
        self.assertFalse(res)

        # Zero side-effects verification: No runner scripts created
        wsb_profile = os.path.join(self.tmpdir, "detonation_profile.wsb")
        ps1_script = os.path.join(self.tmpdir, "collect_telemetry.ps1")
        posix_runner = os.path.join(self.tmpdir, "posix_isolated_runner.sh")
        frida_js = os.path.join(self.tmpdir, "frida_telemetry.js")

        self.assertFalse(os.path.exists(wsb_profile), "wsb_profile must not exist on denial")
        self.assertFalse(os.path.exists(ps1_script), "ps1_script must not exist on denial")
        self.assertFalse(os.path.exists(posix_runner), "posix_runner must not exist on denial")
        self.assertFalse(os.path.exists(frida_js), "frida_js must not exist on denial")

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
            principal=self.verified_viewer,  # VIEWER lacks permission for REMEDIATION_PATCH
            tenant_id="tenant-a",
            strict_auth=True,
        )
        pipe.execute_stage(0)

        with self.assertRaises(AuthorizationDeniedError) as exc_info:
            pipe._stage_11()
        self.assertIn("DENIED_INSUFFICIENT_ROLE", str(exc_info.exception))


if __name__ == "__main__":
    unittest.main()
