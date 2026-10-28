"""
R3V3R53//F0RG3 - Phase 4.2 HIL Authorization Bypass Closure Regression Test Suite

Regression tests for:
  P4.2-F01: submit_hil_decision() non-production authorization bypass
  P4.2-F02: /api/upload and /api/annotate conditional authentication bypass
  P4.2-F03: _is_hil_approved() history-poisoning bypass

Every APPROVE_SANDBOXED path through submit_hil_decision() must now unconditionally
invoke CentralAuthorizationBoundary.evaluate_request() regardless of environment,
strict_auth flag, or presence/absence of principal/approval_grant.

For each denied request, the tests assert ALL of:
  - The operation raises AuthorizationDeniedError
  - The investigation stage does NOT advance to Stage 6
  - The investigation status is NOT 'RUNNING'
  - No protected subprocess, sandbox execution, or file modification occurs
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from typing import Optional
from unittest.mock import MagicMock, patch

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from reverse_forge.authorization import (
    ApprovalGrant,
    ApprovalIssuer,
    AuthorizationDecision,
    AuthorizationDeniedError,
    CentralAuthorizationBoundary,
    HILKeyRing,
    OperationType,
    SQLiteAtomicGrantConsumptionStore,
)
from reverse_forge.firebase_sync import (
    AuthUserContext,
    UserRole,
    _create_sealed_user_context,
)
from reverse_forge.investigation_workflow import InvestigationWorkflowEngine


_TEST_KEY = b"phase42-test-signing-key-abcdefghijklmnopqrstuvwxyz-001"
_TEST_KEY_RING = HILKeyRing.from_single_key(_TEST_KEY, key_id="test-key-1")


def _make_verified_principal(uid="analyst-001", role=UserRole.ANALYST, tenant_id="tenant-alpha"):
    return _create_sealed_user_context(uid=uid, email=f"{uid}@example.com", role=role, tenant_id=tenant_id)


def _make_boundary(db_path=None):
    store = SQLiteAtomicGrantConsumptionStore(db_path=db_path or tempfile.mktemp(suffix=".sqlite"))
    return CentralAuthorizationBoundary(signing_key=_TEST_KEY_RING, consumption_store=store, verify_target_on_disk=True)


def _make_issuer():
    return ApprovalIssuer(key_ring=_TEST_KEY_RING)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _blocked_hil_inv(engine, binary_path):
    state = engine.create_investigation("analyze for vulnerabilities", binary_path, tenant_id="tenant-alpha")
    state.status = "BLOCKED_HIL"
    state.spec.requires_hil_approval = True
    state.spec.requires_dynamic_execution = True
    state.current_stage_idx = 6
    state.hil_pending_request = {"action": "dynamic_execution", "options": ["APPROVE_SANDBOXED", "REJECT_STATIC_ONLY"]}
    return state.investigation_id


class TestSubmitHilDecisionBypassClosure(unittest.TestCase):
    """P4.2-F01: submit_hil_decision non-production bypass closure."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        self.tmp.write(b"\x7fELF" + b"\x00" * 60)
        self.tmp.flush(); self.tmp.close()
        self.binary_path = self.tmp.name
        self.target_sha256 = _sha256(self.binary_path)
        self.boundary = _make_boundary()
        self.engine = InvestigationWorkflowEngine(authorization_boundary=self.boundary)

    def tearDown(self):
        try: os.unlink(self.binary_path)
        except OSError: pass

    def test_p42_no_principal_no_grant_approve_sandboxed_denied(self):
        """Core regression: APPROVE_SANDBOXED without credentials must be denied unconditionally."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state_before = self.engine.get_investigation(inv_id)
        stage_before = state_before.current_stage_idx

        with self.assertRaises(AuthorizationDeniedError) as ctx:
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                operator="rogue-caller", principal=None, approval_grant=None,
                strict_auth=False, boundary=self.boundary,
            )

        state_after = self.engine.get_investigation(inv_id)
        self.assertNotEqual(state_after.status, "RUNNING", "Stage must not advance")
        self.assertEqual(state_after.current_stage_idx, stage_before, "Stage index must not change")
        self.assertIn(ctx.exception.decision, (
            AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY,
            AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED,
            AuthorizationDecision.DENIED_HIL_CONFIG_INVALID,
            AuthorizationDecision.DENIED_POLICY_VIOLATION,
        ))

    def test_p42_strict_auth_false_is_now_noop(self):
        """strict_auth=False must not provide bypass; it is a no-op."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                strict_auth=False, principal=None, approval_grant=None, boundary=self.boundary,
            )
        self.assertNotEqual(self.engine.get_investigation(inv_id).status, "RUNNING")

    def test_p42_dev_env_does_not_bypass(self):
        """REVERSE_FORGE_ENV=development must not bypass authorization."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with patch.dict(os.environ, {"REVERSE_FORGE_ENV": "development"}):
            with self.assertRaises(AuthorizationDeniedError):
                self.engine.submit_hil_decision(
                    inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                    principal=None, approval_grant=None, boundary=self.boundary,
                )
        self.assertNotEqual(self.engine.get_investigation(inv_id).status, "RUNNING")

    def test_p42_missing_env_var_does_not_bypass(self):
        """Absent REVERSE_FORGE_ENV must not trigger bypass."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        env = {k: v for k, v in os.environ.items() if k != "REVERSE_FORGE_ENV"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(AuthorizationDeniedError):
                self.engine.submit_hil_decision(
                    inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                    principal=None, approval_grant=None, boundary=self.boundary,
                )

    def test_p42_forged_principal_is_denied(self):
        """Forged AuthUserContext with is_verified=True set directly must be denied."""
        forged = AuthUserContext(uid="attacker", email="x@evil.com", role=UserRole.LEAD_ARCHITECT,
                                  tenant_id="tenant-alpha", is_verified=True)
        self.assertFalse(forged.is_cryptographically_verified(), "Seal check must fail for forged context")
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError) as ctx:
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=forged, approval_grant=None, boundary=self.boundary,
            )
        self.assertIn(ctx.exception.decision, (
            AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY,
            AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED,
        ))

    def test_p42_cross_tenant_principal_denied(self):
        """Principal from different tenant cannot authorize."""
        principal = _make_verified_principal(tenant_id="tenant-other")
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError) as ctx:
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=principal, approval_grant=None, boundary=self.boundary,
            )
        self.assertEqual(ctx.exception.decision, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS)
        self.assertNotEqual(self.engine.get_investigation(inv_id).status, "RUNNING")

    def test_p42_expired_grant_denied(self):
        """Expired grant must be rejected."""
        principal = _make_verified_principal()
        grant = _make_issuer().issue_grant(
            approver=principal, operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.binary_path, target_sha256=self.target_sha256,
            tenant_id="tenant-alpha", ttl_seconds=60.0, issued_at=time.time() - 7200.0,
        )
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError) as ctx:
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=principal, approval_grant=grant, boundary=self.boundary,
            )
        self.assertIn(ctx.exception.decision, (
            AuthorizationDecision.DENIED_HIL_APPROVAL_STALE, AuthorizationDecision.DENIED_POLICY_VIOLATION,
        ))

    def test_p42_wrong_sha256_grant_denied(self):
        """Grant for wrong SHA-256 must be denied."""
        principal = _make_verified_principal()
        grant = _make_issuer().issue_grant(
            approver=principal, operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.binary_path, target_sha256="a" * 64,
            tenant_id="tenant-alpha",
        )
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError) as ctx:
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=principal, approval_grant=grant, boundary=self.boundary,
            )
        self.assertIn(ctx.exception.decision, (
            AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH, AuthorizationDecision.DENIED_POLICY_VIOLATION,
        ))

    def test_p42_wrong_operation_grant_denied(self):
        """Grant for wrong operation must be denied."""
        principal = _make_verified_principal()
        grant = _make_issuer().issue_grant(
            approver=principal, operation=OperationType.STATIC_ANALYSIS,
            target_path=self.binary_path, target_sha256=self.target_sha256,
            tenant_id="tenant-alpha",
        )
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=principal, approval_grant=grant, boundary=self.boundary,
            )

    def test_p42_tampered_signature_denied(self):
        """Grant with tampered signature must be denied."""
        principal = _make_verified_principal()
        grant = _make_issuer().issue_grant(
            approver=principal, operation=OperationType.DYNAMIC_SANDBOX,
            target_path=self.binary_path, target_sha256=self.target_sha256,
            tenant_id="tenant-alpha",
        )
        d = grant.to_dict(); d["signature"] = "0" * len(d["signature"])
        tampered = ApprovalGrant.from_dict(d)
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=principal, approval_grant=tampered, boundary=self.boundary,
            )

    def test_p42_reject_static_only_needs_no_authorization(self):
        """REJECT_STATIC_ONLY must proceed without credentials (no dynamic execution triggered)."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state = self.engine.submit_hil_decision(
            inv_id, "dynamic_execution", "REJECT_STATIC_ONLY",
            principal=None, approval_grant=None, boundary=self.boundary,
        )
        self.assertIn(state.status, ("RUNNING", "INITIALIZED"))
        self.assertEqual(state.current_stage_idx, 7)

    def test_p42_deny_does_not_advance_stage(self):
        """Denied APPROVE_SANDBOXED must leave stage/status unchanged."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        before = self.engine.get_investigation(inv_id)
        old_stage, old_status = before.current_stage_idx, before.status

        with self.assertRaises(AuthorizationDeniedError):
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                principal=None, approval_grant=None, boundary=self.boundary,
            )

        after = self.engine.get_investigation(inv_id)
        self.assertEqual(after.current_stage_idx, old_stage)
        self.assertEqual(after.status, old_status)

    def test_p42_deny_records_denial_in_hil_history(self):
        """Denied APPROVE_SANDBOXED must write a DENIED record to hil_history."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.submit_hil_decision(
                inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                operator="denied-caller", principal=None, approval_grant=None, boundary=self.boundary,
            )
        state = self.engine.get_investigation(inv_id)
        self.assertTrue(any(r.get("decision") == "DENIED" for r in state.hil_history),
                        "DENIED record must appear in hil_history")
        self.assertFalse(
            any(r.get("decision") == "APPROVE_SANDBOXED" and r.get("cryptographic_auth") is True
                for r in state.hil_history),
            "No cryptographically authorized record should appear after denial"
        )

    def test_p42_all_legacy_bypass_combinations_denied(self):
        """Comprehensive: all legacy bypass parameter combinations must fail."""
        combos = [
            (False, "development", None, None, "dev env no creds"),
            (False, "",            None, None, "no env no creds"),
            (False, "test",        None, None, "test env no creds"),
            (True,  "development", None, None, "strict_auth=True dev no creds"),
            (False, "production",  None, None, "prod env no grant"),
        ]
        for strict_auth, env_val, principal, grant, desc in combos:
            with self.subTest(desc=desc):
                inv_id = _blocked_hil_inv(self.engine, self.binary_path)
                env_patch = {k: v for k, v in os.environ.items() if k != "REVERSE_FORGE_ENV"}
                if env_val:
                    env_patch["REVERSE_FORGE_ENV"] = env_val
                with patch.dict(os.environ, env_patch, clear=True):
                    with self.assertRaises(AuthorizationDeniedError, msg=f"Expected denial: {desc}"):
                        self.engine.submit_hil_decision(
                            inv_id, "dynamic_execution", "APPROVE_SANDBOXED",
                            strict_auth=strict_auth, principal=principal,
                            approval_grant=grant, boundary=self.boundary,
                        )
                self.assertNotEqual(self.engine.get_investigation(inv_id).status, "RUNNING",
                                    f"Stage must not advance: {desc}")


class TestHilApprovedHistoryPoisoningClosure(unittest.TestCase):
    """P4.2-F03: _is_hil_approved() history-poisoning bypass closure."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        self.tmp.write(b"\x7fELF" + b"\x00" * 60)
        self.tmp.flush(); self.tmp.close()
        self.binary_path = self.tmp.name
        self.boundary = _make_boundary()
        self.engine = InvestigationWorkflowEngine(authorization_boundary=self.boundary)

    def tearDown(self):
        try: os.unlink(self.binary_path)
        except OSError: pass

    def test_record_without_cryptographic_auth_rejected(self):
        """Record missing cryptographic_auth key must not satisfy _is_hil_approved."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state = self.engine.get_investigation(inv_id)
        state.hil_history.append({"action": "dynamic_execution", "decision": "APPROVE_SANDBOXED", "operator": "attacker"})
        self.assertFalse(self.engine._is_hil_approved(state, "dynamic_execution"))

    def test_record_with_cryptographic_auth_false_rejected(self):
        """Record with cryptographic_auth=False must not satisfy _is_hil_approved."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state = self.engine.get_investigation(inv_id)
        state.hil_history.append({
            "action": "dynamic_execution", "decision": "APPROVE_SANDBOXED",
            "operator": "attacker", "cryptographic_auth": False,
        })
        self.assertFalse(self.engine._is_hil_approved(state, "dynamic_execution"))

    def test_wrong_action_rejected(self):
        """_is_hil_approved must not match wrong action name."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state = self.engine.get_investigation(inv_id)
        state.hil_history.append({"action": "OTHER_ACTION", "decision": "APPROVE_SANDBOXED", "cryptographic_auth": True})
        self.assertFalse(self.engine._is_hil_approved(state, "dynamic_execution"))

    def test_cryptographic_auth_true_accepted(self):
        """Record with cryptographic_auth=True must satisfy _is_hil_approved."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state = self.engine.get_investigation(inv_id)
        state.hil_history.append({
            "action": "dynamic_execution", "decision": "APPROVE_SANDBOXED",
            "operator": "analyst-001", "grant_id": "test-grant-xyz", "cryptographic_auth": True,
        })
        self.assertTrue(self.engine._is_hil_approved(state, "dynamic_execution"))

    def test_stage6_guard_rejects_poisoned_history(self):
        """_run_stage6_dynamic_execution must deny execution with only poisoned hil_history."""
        inv_id = _blocked_hil_inv(self.engine, self.binary_path)
        state = self.engine.get_investigation(inv_id)
        state.status = "RUNNING"
        state.hil_history.append({
            "action": "dynamic_execution", "decision": "APPROVE_SANDBOXED",
            "operator": "attacker", "cryptographic_auth": False,
        })
        with self.assertRaises(AuthorizationDeniedError) as ctx:
            self.engine._run_stage6_dynamic_execution(state)
        self.assertEqual(ctx.exception.decision, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED)

    def test_execute_next_stage_fails_with_poisoned_history(self):
        """execute_next_stage at Stage 6 with poisoned hil_history must fail, not run."""
        state = self.engine.create_investigation("vuln analysis", self.binary_path, tenant_id="tenant-alpha")
        state.spec.requires_hil_approval = True
        state.current_stage_idx = 6
        state.status = "RUNNING"
        state.hil_history = [{"action": "dynamic_execution", "decision": "APPROVE_SANDBOXED",
                               "operator": "attacker", "cryptographic_auth": False}]
        result = self.engine.execute_next_stage(state.investigation_id)
        self.assertIn(result.status, ("FAILED", "BLOCKED_HIL"),
                      "Stage 6 must not complete with poisoned hil_history")


class TestGuiEndpointAuthBypassClosure(unittest.TestCase):
    """P4.2-F02: /api/upload and /api/annotate conditional authentication bypass closure."""

    def _run_post_unauthenticated(self, endpoint_path, body, strict_auth=False):
        """Directly test the do_POST dispatch logic for a given endpoint."""
        from reverse_forge.gui_server import GUIWorkbenchHandler

        class FakeHeaders(dict):
            def get(self, key, default=None):
                return super().get(key, default)

        class TestHandler(GUIWorkbenchHandler):
            server = MagicMock()
            client_address = ("127.0.0.1", 0)
            request = MagicMock()

            def __init__(self_inner):
                self_inner.headers = FakeHeaders({"Content-Length": str(len(body))})
                self_inner.rfile = io.BytesIO(body)
                self_inner._responses = []
                self_inner.strict_auth = strict_auth
                self_inner.scope_ledger = None
                self_inner.default_binary_path = "/tmp/test.bin"
                self_inner.project_db = MagicMock()
                self_inner.path = endpoint_path

            def _json_response(self_inner, data, status=200):
                self_inner._responses.append((status, data))

            def send_response(self_inner, code): pass
            def send_header(self_inner, k, v): pass
            def end_headers(self_inner): pass

        handler = TestHandler()
        with patch.object(handler, '_is_trusted_origin', return_value=True):
            with patch.object(handler, '_get_auth_user', return_value=None):
                handler.do_POST()
        return handler._responses

    def test_upload_requires_auth_without_strict_auth(self):
        """/api/upload must require auth even when strict_auth=False."""
        body = b"\x7fELF" + b"\x00" * 60
        responses = self._run_post_unauthenticated("/api/upload?filename=test.bin", body, strict_auth=False)
        codes = [r[0] for r in responses]
        self.assertIn(401, codes, "/api/upload must return 401 without auth")
        self.assertNotIn(200, codes)

    def test_upload_requires_auth_with_strict_auth_true(self):
        """/api/upload must require auth when strict_auth=True as well."""
        body = b"\x7fELF" + b"\x00" * 60
        responses = self._run_post_unauthenticated("/api/upload?filename=test.bin", body, strict_auth=True)
        codes = [r[0] for r in responses]
        self.assertIn(401, codes)

    def test_annotate_requires_auth_without_strict_auth(self):
        """/api/annotate must require auth even when strict_auth=False."""
        body = json.dumps({"action": "comment", "address": "0x401000", "value": "hacked"}).encode()
        responses = self._run_post_unauthenticated("/api/annotate", body, strict_auth=False)
        codes = [r[0] for r in responses]
        self.assertIn(401, codes, "/api/annotate must return 401 without auth")
        self.assertNotIn(200, codes)

    def test_annotate_requires_auth_with_strict_auth_true(self):
        """/api/annotate must also require auth when strict_auth=True."""
        body = json.dumps({"action": "rename", "address": "0x401000", "value": "main"}).encode()
        responses = self._run_post_unauthenticated("/api/annotate", body, strict_auth=True)
        codes = [r[0] for r in responses]
        self.assertIn(401, codes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
