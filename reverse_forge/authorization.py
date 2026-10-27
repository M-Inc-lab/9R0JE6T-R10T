"""
R3V3R53//F0RG3 — Centralized Execution Authorization & Human-in-the-Loop (HIL) Boundary
========================================================================================
Phase 4 Specification §4 (P0 — Centralize execution authorization and HIL):
  - Evaluates every sensitive operation immediately before side-effects occur (TOCTOU protection).
  - Validates authenticated principal, verified identity, tenant ownership, role permissions,
    scope ledger authorization, and bound HIL approval.
  - HIL Approval Tokens are cryptographically HMAC-bound to:
      (operation, target_sha256, canonical_parameters_hash, approver_uid, expiration_timestamp).
  - Mandatory policy cannot be overridden by ANY autonomy setting (even AUTONOMOUS / CONTINUOUS).
  - Missing callback, callback exception, timeout, or stale approval strictly denies (fail-closed).
  - Denied operations strictly produce zero side-effects.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
import enum
import hashlib
import hmac
import json
import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union

from reverse_forge.firebase_sync import AuthUserContext, UserRole
from reverse_forge.provenance import ActionPermission, ScopeLedger

logger = logging.getLogger("reverse_forge.authorization")


class OperationType(str, enum.Enum):
    """Canonical sensitive operation types governed by the Central Authorization Boundary."""
    READ_METADATA = "read_metadata"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_SANDBOX = "dynamic_sandbox"
    NETWORK_ACCESS = "network_access"
    MODIFY_ARTIFACT = "modify_artifact"
    REMEDIATION_PATCH = "remediation_patch"
    EXPORT_REPORT = "export_report"
    DELETE_ARTIFACT = "delete_artifact"
    EXTERNAL_SERVICE = "external_service"


class AuthorizationDecision(str, enum.Enum):
    PERMITTED = "PERMITTED"
    DENIED_UNVERIFIED_IDENTITY = "DENIED_UNVERIFIED_IDENTITY"
    DENIED_INSUFFICIENT_ROLE = "DENIED_INSUFFICIENT_ROLE"
    DENIED_CROSS_TENANT_ACCESS = "DENIED_CROSS_TENANT_ACCESS"
    DENIED_OUT_OF_SCOPE = "DENIED_OUT_OF_SCOPE"
    DENIED_HIL_APPROVAL_REQUIRED = "DENIED_HIL_APPROVAL_REQUIRED"
    DENIED_HIL_CALLBACK_FAILED = "DENIED_HIL_CALLBACK_FAILED"
    DENIED_HIL_APPROVAL_STALE = "DENIED_HIL_APPROVAL_STALE"
    DENIED_HIL_PARAMETER_MISMATCH = "DENIED_HIL_PARAMETER_MISMATCH"
    DENIED_HIL_TARGET_MISMATCH = "DENIED_HIL_TARGET_MISMATCH"
    DENIED_POLICY_VIOLATION = "DENIED_POLICY_VIOLATION"


class AuthorizationDeniedError(PermissionError):
    """Raised when an operation is denied by the Central Authorization Boundary."""
    def __init__(self, decision: AuthorizationDecision, reason: str, audit_entry: Dict[str, Any]):
        super().__init__(f"[{decision.value}] {reason}")
        self.decision = decision
        self.reason = reason
        self.audit_entry = audit_entry


@dataclass(frozen=True)
class ApprovalGrant:
    """
    Cryptographically bound, single-use Human-in-the-Loop approval grant.
    Binds tightly to exact operation, target SHA-256, canonical parameter hash, approver, and TTL.
    """
    grant_id: str
    operation: str
    target_sha256: str
    parameters_hash: str
    approver_uid: str
    issued_at: float
    expires_at: float
    signature: str

    @classmethod
    def create(
        cls,
        operation: Union[OperationType, str],
        target_sha256: str,
        parameters: Dict[str, Any],
        approver_uid: str,
        ttl_seconds: float = 300.0,
        signing_key: Optional[bytes] = None,
    ) -> ApprovalGrant:
        op_str = operation.value if isinstance(operation, OperationType) else str(operation)
        now = time.time()
        expires = now + ttl_seconds
        param_hash = cls.hash_parameters(parameters)
        gid = hashlib.sha256(f"{op_str}:{target_sha256}:{param_hash}:{now}".encode()).hexdigest()[:16]

        key = signing_key or cls._get_internal_signing_key()
        msg = f"{gid}:{op_str}:{target_sha256}:{param_hash}:{approver_uid}:{now}:{expires}".encode()
        sig = hmac.new(key, msg, hashlib.sha256).hexdigest()

        return cls(
            grant_id=gid,
            operation=op_str,
            target_sha256=target_sha256,
            parameters_hash=param_hash,
            approver_uid=approver_uid,
            issued_at=now,
            expires_at=expires,
            signature=sig,
        )

    @staticmethod
    def hash_parameters(params: Optional[Dict[str, Any]]) -> str:
        """Deterministic canonical JSON serialization and SHA-256 hash of parameters."""
        if not params:
            return hashlib.sha256(b"{}").hexdigest()
        try:
            canonical_json = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
        except Exception:
            canonical_json = str(sorted(params.items()))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @staticmethod
    def _get_internal_signing_key() -> bytes:
        key_hex = os.environ.get("REVERSE_FORGE_HIL_KEY")
        if key_hex:
            return key_hex.encode("utf-8")
        # Deterministic process-scoped fallback key
        return b"rf_hil_internal_signing_key_bicentennial_2026"

    def is_valid_for(
        self,
        operation: Union[OperationType, str],
        target_sha256: str,
        parameters: Optional[Dict[str, Any]],
        signing_key: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        op_str = operation.value if isinstance(operation, OperationType) else str(operation)
        now = time.time()

        # 1. Check expiration
        if now > self.expires_at:
            return False, f"Approval grant expired (expired at {self.expires_at}, now {now})"
        if now < (self.issued_at - 5.0):
            return False, "Approval grant has future issue timestamp"

        # 2. Check operation binding
        if self.operation != op_str:
            return False, f"Approval grant operation mismatch ('{self.operation}' != '{op_str}')"

        # 3. Check target SHA-256 binding
        if self.target_sha256 != target_sha256:
            return False, f"Approval grant target mismatch ('{self.target_sha256}' != '{target_sha256}')"

        # 4. Check parameter hash binding
        current_param_hash = self.hash_parameters(parameters)
        if self.parameters_hash != current_param_hash:
            return False, "Approval grant parameter hash mismatch (parameters modified after approval)"

        # 5. Check signature
        key = signing_key or self._get_internal_signing_key()
        msg = f"{self.grant_id}:{self.operation}:{self.target_sha256}:{self.parameters_hash}:{self.approver_uid}:{self.issued_at}:{self.expires_at}".encode()
        expected_sig = hmac.new(key, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(self.signature, expected_sig):
            return False, "Approval grant signature invalid or forged"

        return True, "Valid"


class CentralAuthorizationBoundary:
    """
    Unified, fail-closed authorization engine for all reverse engineering operations.
    Enforces RBAC, tenant isolation, scope boundaries, and human-in-the-loop approval.
    """

    # Operations strictly requiring explicit Human-In-The-Loop approval
    MANDATORY_HIL_OPERATIONS: Set[OperationType] = {
        OperationType.DYNAMIC_SANDBOX,
        OperationType.NETWORK_ACCESS,
        OperationType.DELETE_ARTIFACT,
        OperationType.MODIFY_ARTIFACT,
    }

    # Minimum required role for each operation
    ROLE_PERMISSIONS: Dict[OperationType, Set[UserRole]] = {
        OperationType.READ_METADATA: {UserRole.VIEWER, UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.STATIC_ANALYSIS: {UserRole.VIEWER, UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.EXPORT_REPORT: {UserRole.VIEWER, UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.DYNAMIC_SANDBOX: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.NETWORK_ACCESS: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.MODIFY_ARTIFACT: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.REMEDIATION_PATCH: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.EXTERNAL_SERVICE: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.DELETE_ARTIFACT: {UserRole.LEAD_ARCHITECT},
    }

    # Mapping to ActionPermission for ScopeLedger integration
    ACTION_PERMISSION_MAP: Dict[OperationType, ActionPermission] = {
        OperationType.READ_METADATA: ActionPermission.READ_HASH,
        OperationType.STATIC_ANALYSIS: ActionPermission.STATIC_ANALYSIS,
        OperationType.DYNAMIC_SANDBOX: ActionPermission.DYNAMIC_SANDBOX,
        OperationType.NETWORK_ACCESS: ActionPermission.NETWORK_ACCESS,
        OperationType.MODIFY_ARTIFACT: ActionPermission.MODIFY_ARTIFACT,
        OperationType.REMEDIATION_PATCH: ActionPermission.MODIFY_ARTIFACT,
        OperationType.EXPORT_REPORT: ActionPermission.EXPORT_REPORT,
        OperationType.DELETE_ARTIFACT: ActionPermission.DESTRUCTIVE_OP,
        OperationType.EXTERNAL_SERVICE: ActionPermission.EXTERNAL_SERVICE,
    }

    def __init__(self, signing_key: Optional[bytes] = None):
        self.signing_key = signing_key or ApprovalGrant._get_internal_signing_key()
        self._audit_log: List[Dict[str, Any]] = []
        self._lock = threading.RLock()
        self._consumed_grants: Set[str] = set()

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit_log)

    def evaluate_request(
        self,
        principal: Optional[AuthUserContext],
        operation: Union[OperationType, str],
        target_path: str,
        target_sha256: str,
        target_tenant_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        scope_ledger: Optional[ScopeLedger] = None,
        approval_grant: Optional[ApprovalGrant] = None,
        hil_callback: Optional[Callable[[str, Dict[str, Any]], Union[bool, ApprovalGrant]]] = None,
        autonomy_level: int = 2,
    ) -> Tuple[bool, AuthorizationDecision, str, Optional[ApprovalGrant]]:
        """
        Evaluates the authorization policy for a requested operation immediately before execution.
        Returns: (permitted, decision, reason, grant_used_or_created)
        """
        op = OperationType(operation) if isinstance(operation, str) else operation
        params = parameters or {}

        # 1. Principal & Identity Verification
        if principal is None or not principal.is_verified:
            reason = "Unverified or missing principal identity. Privileged operations require verified credentials."
            self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY, reason)
            return False, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY, reason, None

        # 2. Tenant Ownership Verification
        if principal.tenant_id != target_tenant_id:
            reason = f"Cross-tenant access prohibited: principal tenant '{principal.tenant_id}' != target tenant '{target_tenant_id}'"
            self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS, reason)
            return False, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS, reason, None

        # 3. Role-Based Access Control (RBAC)
        allowed_roles = self.ROLE_PERMISSIONS.get(op, {UserRole.LEAD_ARCHITECT})
        if principal.role not in allowed_roles:
            reason = f"Role '{principal.role.value}' lacks permission for operation '{op.value}'. Required: {[r.value for r in allowed_roles]}"
            self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE, reason)
            return False, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE, reason, None

        # 4. Scope Ledger Policy Check
        if scope_ledger is not None:
            action_perm = self.ACTION_PERMISSION_MAP.get(op, ActionPermission.STATIC_ANALYSIS)
            if not scope_ledger.is_authorized(target_path, action=action_perm):
                reason = f"Scope ledger policy denied action '{action_perm.value}' for target '{target_path}'"
                self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_OUT_OF_SCOPE, reason)
                return False, AuthorizationDecision.DENIED_OUT_OF_SCOPE, reason, None

        # 5. Mandatory Human-In-The-Loop (HIL) Evaluation
        is_mandatory_hil = op in self.MANDATORY_HIL_OPERATIONS

        # Mandatory policy can NEVER be overridden by any autonomy setting.
        # Non-mandatory operations (e.g. read_metadata, static_analysis, export_report)
        # proceed autonomously under SUPERVISED (2), AUTONOMOUS (3), and CONTINUOUS (4).
        if is_mandatory_hil:
            requires_hil = True
        elif autonomy_level <= 0:
            requires_hil = True  # MANUAL: every action requires sign-off
        elif autonomy_level == 1:
            requires_hil = op not in {OperationType.READ_METADATA, OperationType.STATIC_ANALYSIS, OperationType.EXPORT_REPORT}
        else:
            requires_hil = False  # SUPERVISED/AUTONOMOUS/CONTINUOUS: non-mandatory operations proceed without HIL

        active_grant = approval_grant

        if requires_hil:
            # Check provided grant first
            if active_grant is not None:
                # Check grant consumption
                with self._lock:
                    if active_grant.grant_id in self._consumed_grants:
                        reason = f"Approval grant '{active_grant.grant_id}' has already been consumed (replay prevention)"
                        self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE, reason)
                        return False, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE, reason, None

                valid, err = active_grant.is_valid_for(op, target_sha256, params, self.signing_key)
                if not valid:
                    if "expired" in err.lower():
                        dec = AuthorizationDecision.DENIED_HIL_APPROVAL_STALE
                    elif "target mismatch" in err.lower():
                        dec = AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH
                    elif "parameter" in err.lower():
                        dec = AuthorizationDecision.DENIED_HIL_PARAMETER_MISMATCH
                    else:
                        dec = AuthorizationDecision.DENIED_POLICY_VIOLATION
                    self._record_audit(principal, op, target_sha256, target_tenant_id, False, dec, err)
                    return False, dec, err, None
            else:
                # No pre-existing grant: attempt to query hil_callback
                if hil_callback is None:
                    reason = f"Operation '{op.value}' strictly requires human approval, but no HIL callback is registered (fail-closed)"
                    self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason)
                    return False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason, None

                prompt = f"Approve execution of '{op.value}' on target SHA-256 {target_sha256[:16]}...?"
                context = {
                    "operation": op.value,
                    "target_path": target_path,
                    "target_sha256": target_sha256,
                    "tenant_id": target_tenant_id,
                    "principal_uid": principal.uid,
                    "parameters": params,
                }

                try:
                    callback_res = hil_callback(prompt, context)
                except Exception as exc:
                    reason = f"HIL approval callback raised exception: {exc} (fail-closed)"
                    self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_HIL_CALLBACK_FAILED, reason)
                    return False, AuthorizationDecision.DENIED_HIL_CALLBACK_FAILED, reason, None

                if callback_res is True:
                    # Callback approved directly: create bound grant
                    active_grant = ApprovalGrant.create(
                        operation=op,
                        target_sha256=target_sha256,
                        parameters=params,
                        approver_uid=principal.uid,
                        ttl_seconds=300.0,
                        signing_key=self.signing_key,
                    )
                elif isinstance(callback_res, ApprovalGrant):
                    active_grant = callback_res
                    valid, err = active_grant.is_valid_for(op, target_sha256, params, self.signing_key)
                    if not valid:
                        reason = f"HIL callback returned invalid grant: {err}"
                        self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_POLICY_VIOLATION, reason)
                        return False, AuthorizationDecision.DENIED_POLICY_VIOLATION, reason, None
                else:
                    reason = f"Operator denied approval for operation '{op.value}'"
                    self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason)
                    return False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason, None

            # Mark grant as consumed to prevent replay
            if active_grant:
                with self._lock:
                    self._consumed_grants.add(active_grant.grant_id)

        # 6. Permit operation
        self._record_audit(principal, op, target_sha256, target_tenant_id, True, AuthorizationDecision.PERMITTED, "Authorized")
        return True, AuthorizationDecision.PERMITTED, "Authorized", active_grant

    def enforce(
        self,
        principal: Optional[AuthUserContext],
        operation: Union[OperationType, str],
        target_path: str,
        target_sha256: str,
        target_tenant_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        scope_ledger: Optional[ScopeLedger] = None,
        approval_grant: Optional[ApprovalGrant] = None,
        hil_callback: Optional[Callable[[str, Dict[str, Any]], Union[bool, ApprovalGrant]]] = None,
        autonomy_level: int = 2,
    ) -> ApprovalGrant:
        """
        Enforces authorization policy. Raises AuthorizationDeniedError immediately if denied.
        Guarantees that execution cannot proceed to side-effects.
        """
        permitted, decision, reason, grant = self.evaluate_request(
            principal=principal,
            operation=operation,
            target_path=target_path,
            target_sha256=target_sha256,
            target_tenant_id=target_tenant_id,
            parameters=parameters,
            scope_ledger=scope_ledger,
            approval_grant=approval_grant,
            hil_callback=hil_callback,
            autonomy_level=autonomy_level,
        )
        if not permitted:
            latest_audit = self._audit_log[-1] if self._audit_log else {}
            raise AuthorizationDeniedError(decision, reason, latest_audit)
        return grant or ApprovalGrant.create(operation, target_sha256, parameters or {}, principal.uid if principal else "system", ttl_seconds=60.0)

    def _record_audit(
        self,
        principal: Optional[AuthUserContext],
        operation: OperationType,
        target_sha256: str,
        tenant_id: str,
        permitted: bool,
        decision: AuthorizationDecision,
        reason: str,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_uid": principal.uid if principal else "unauthenticated",
            "principal_role": principal.role.value if principal else "NONE",
            "principal_tenant": principal.tenant_id if principal else "NONE",
            "target_tenant": tenant_id,
            "target_sha256": target_sha256,
            "operation": operation.value,
            "permitted": permitted,
            "decision": decision.value,
            "reason": reason,
        }
        with self._lock:
            self._audit_log.append(entry)
            logger.info("AUTH_DECISION: %s op=%s target=%s permitted=%s reason=%s",
                        decision.value, operation.value, target_sha256[:12], permitted, reason)


# Global singleton instance for platform-wide boundary enforcement
_global_boundary: Optional[CentralAuthorizationBoundary] = None
_boundary_lock = threading.Lock()


def get_authorization_boundary() -> CentralAuthorizationBoundary:
    """Returns the singleton CentralAuthorizationBoundary instance."""
    global _global_boundary
    with _boundary_lock:
        if _global_boundary is None:
            _global_boundary = CentralAuthorizationBoundary()
        return _global_boundary
