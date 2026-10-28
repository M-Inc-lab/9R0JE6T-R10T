"""
R3V3R53//F0RG3 — Centralized Execution Authorization & Human-in-the-Loop (HIL) Boundary
========================================================================================
Phase 4 & Phase 4.1 Hardened Implementation:
  - Eliminates all hard-coded or implicit fallback signing keys; missing, empty, malformed,
    or weak (<256-bit) signing-key configuration fails closed for sensitive operations.
  - Supports explicit key management and zero-downtime key rotation via `HILKeyRing`.
  - Separates approval issuance (`ApprovalIssuer`) from approval verification (`ApprovalGrant`
    and `CentralAuthorizationBoundary`). Callers cannot mint approvals by constructing an
    `ApprovalGrant` or without an authenticated, role-authorized approver.
  - Binds each grant to: `(grant_id, key_id, tenant_id, operation, canonical_target_path,
    target_sha256, canonical_parameters_hash, approver_uid, approver_role, issued_at, expires_at)`.
  - Uses strict canonical JSON serialization (`allow_nan=False`, no `default=str` or fallback).
  - Enforces atomic, persistent single-use grant consumption (`SQLiteAtomicGrantConsumptionStore`
    and `FirestoreTransactionalGrantConsumptionStore`) across threads, worker processes, and restarts.
  - Revalidates on-disk target SHA-256 immediately before execution to defeat TOCTOU file swaps.
"""

from __future__ import annotations

import abc
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import enum
import hashlib
import hmac
import json
import logging
import math
import os
import re
import sqlite3
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from reverse_forge.firebase_sync import (
    AuthUserContext,
    UserRole,
    validate_document_id,
    validate_tenant_id,
)
from reverse_forge.provenance import ActionPermission, ScopeLedger

logger = logging.getLogger("reverse_forge.authorization")

MIN_SIGNING_KEY_BYTES: int = 32
MAX_GRANT_TTL_SECONDS: float = 3600.0
MIN_GRANT_TTL_SECONDS: float = 0.001
MAX_CLOCK_SKEW_SECONDS: float = 5.0

_STRICT_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_GRANT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_KNOWN_FORBIDDEN_KEYS: Set[bytes] = {
    b"rf_hil_internal_signing_key_bicentennial_2026",
    b"default",
    b"secret",
    b"password",
    b"changeme",
}


class HILConfigurationError(RuntimeError):
    """Raised when HIL signing/verification key configuration is missing, malformed, or weak."""


class GrantStorageError(RuntimeError):
    """Raised when the single-use grant consumption store encounters a persistence failure."""


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
    DENIED_HIL_CONFIG_INVALID = "DENIED_HIL_CONFIG_INVALID"
    DENIED_STORAGE_FAILURE = "DENIED_STORAGE_FAILURE"
    DENIED_POLICY_VIOLATION = "DENIED_POLICY_VIOLATION"


class AuthorizationDeniedError(PermissionError):
    """Raised when an operation is denied by the Central Authorization Boundary."""
    def __init__(self, decision: AuthorizationDecision, reason: str, audit_entry: Dict[str, Any]):
        super().__init__(f"[{decision.value}] {reason}")
        self.decision = decision
        self.reason = reason
        self.audit_entry = audit_entry


def normalize_and_validate_signing_key(raw_key: Any, label: str = "signing_key") -> bytes:
    """
    Validate that a signing/verification key is present, properly typed, at least 256 bits
    (32 bytes), not a forbidden/predictable fallback, and possesses sufficient byte diversity.
    """
    if raw_key is None:
        raise HILConfigurationError(f"Missing {label}: HIL signing key is not configured (fail-closed)")
    if isinstance(raw_key, str):
        key_bytes = raw_key.encode("utf-8")
    elif isinstance(raw_key, (bytes, bytearray)):
        key_bytes = bytes(raw_key)
    else:
        raise HILConfigurationError(f"Invalid {label} type: expected bytes or str, got {type(raw_key).__name__}")

    if not key_bytes:
        raise HILConfigurationError(f"Empty {label} is not permitted (fail-closed)")
    if key_bytes in _KNOWN_FORBIDDEN_KEYS or b"rf_hil_internal_signing_key" in key_bytes:
        raise HILConfigurationError(f"Forbidden predictable or fallback {label} rejected")
    if len(key_bytes) < MIN_SIGNING_KEY_BYTES:
        raise HILConfigurationError(
            f"Inadequately strong {label}: minimum {MIN_SIGNING_KEY_BYTES} bytes required, got {len(key_bytes)}"
        )
    if len(set(key_bytes)) < 8:
        raise HILConfigurationError(
            f"Inadequately strong {label}: key lacks sufficient entropy/byte diversity"
        )
    return key_bytes


def canonicalize_target_path(target_path: str) -> str:
    """Validate and canonicalize a target path for grant binding."""
    if not isinstance(target_path, str) or not target_path.strip():
        raise ValueError("target_path must be a non-empty string")
    if "\x00" in target_path or "../" in target_path or "..\\" in target_path:
        raise ValueError(f"Invalid target_path (traversal or null byte rejected): {target_path!r}")
    return os.path.realpath(os.path.abspath(target_path))


def validate_strict_sha256(target_sha256: str) -> str:
    """Validate that target_sha256 is a canonical 64-character hex SHA-256 digest."""
    if not isinstance(target_sha256, str) or not _STRICT_SHA256_RE.match(target_sha256):
        raise ValueError(
            f"Invalid target_sha256: must be a 64-character hexadecimal SHA-256 digest, got {target_sha256!r}"
        )
    return target_sha256.lower()


def _validate_strict_json_value(val: Any, path: str = "$") -> None:
    """Recursively ensure all parameter keys and values are strict JSON-native types."""
    if val is None or isinstance(val, (bool, int, str)):
        return
    if isinstance(val, float):
        if not math.isfinite(val):
            raise ValueError(f"Non-finite float value at {path} is forbidden in canonical parameters")
        return
    if isinstance(val, list):
        for idx, item in enumerate(val):
            _validate_strict_json_value(item, f"{path}[{idx}]")
        return
    if isinstance(val, dict):
        for k, v in val.items():
            if not isinstance(k, str):
                raise TypeError(f"Parameter dictionary key at {path} must be str, got {type(k).__name__}")
            _validate_strict_json_value(v, f"{path}.{k}")
        return
    raise TypeError(
        f"Unsupported non-JSON type '{type(val).__name__}' at {path}: strict canonical serialization rejects arbitrary objects"
    )


def _canonical_grant_signing_payload(
    grant_id: str,
    key_id: str,
    tenant_id: str,
    operation: str,
    target_path: str,
    target_sha256: str,
    parameters_hash: str,
    approver_uid: str,
    approver_role: str,
    issued_at: float,
    expires_at: float,
) -> bytes:
    """
    Construct an unambiguous, canonical JSON envelope for HMAC signing and verification.
    Length-safe JSON object fields prevent delimiter-injection attacks across fields.
    """
    envelope = {
        "v": 2,
        "gid": grant_id,
        "kid": key_id,
        "tid": tenant_id,
        "op": operation,
        "tpath": target_path,
        "tsha": target_sha256.lower(),
        "phash": parameters_hash.lower(),
        "auid": approver_uid,
        "arole": approver_role,
        "iat": round(float(issued_at), 6),
        "exp": round(float(expires_at), 6),
    }
    return json.dumps(envelope, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


class HILKeyRing:
    """
    Explicit secret management and key-rotation keyring for HIL approval grants.
    Supports:
      - An active signing key (`active_key_id`, `active_key`) used to sign newly issued grants.
      - A dictionary of verification keys (`key_id -> key_bytes`) allowing seamless verification
        of grants issued under a previous key during key rotation, and explicit retirement/revocation
        of old keys.
      - Loading from environment variables (`REVERSE_FORGE_HIL_KEY`, `REVERSE_FORGE_HIL_KEY_ID`,
        `REVERSE_FORGE_HIL_VERIFY_KEYS_JSON`) or a secret mount file (`REVERSE_FORGE_HIL_KEY_FILE`).
    """

    def __init__(
        self,
        active_key: Optional[Union[bytes, str]] = None,
        active_key_id: str = "primary",
        verification_keys: Optional[Dict[str, Union[bytes, str]]] = None,
        keys: Optional[Dict[str, Union[bytes, str]]] = None,
    ) -> None:
        if keys is not None:
            if not isinstance(keys, dict) or not keys:
                raise HILConfigurationError("keys must be a non-empty dictionary of key_id -> key_material")
            if active_key_id not in keys:
                if active_key_id == "primary" and len(keys) == 1:
                    active_key_id = next(iter(keys.keys()))
                else:
                    raise HILConfigurationError(f"active_key_id {active_key_id!r} not found in keys")
            active_key = keys[active_key_id]
            merged_verify = dict(keys)
            if verification_keys:
                merged_verify.update(verification_keys)
            verification_keys = merged_verify
        if active_key is None:
            raise HILConfigurationError("HILKeyRing requires active_key or keys dictionary")
        if not isinstance(active_key_id, str) or not _KEY_ID_RE.match(active_key_id):
            raise HILConfigurationError(f"Invalid active_key_id: {active_key_id!r}")
        self.active_key_id: str = active_key_id
        self.active_key: bytes = normalize_and_validate_signing_key(active_key, f"active_key[{active_key_id}]")
        self._keys: Dict[str, bytes] = {self.active_key_id: self.active_key}
        if verification_keys:
            for kid, k_raw in verification_keys.items():
                if not isinstance(kid, str) or not _KEY_ID_RE.match(kid):
                    raise HILConfigurationError(f"Invalid verification key_id: {kid!r}")
                self._keys[kid] = normalize_and_validate_signing_key(k_raw, f"verification_key[{kid}]")
        self._lock = threading.RLock()

    @classmethod
    def from_single_key(cls, key: Union[bytes, str], key_id: str = "primary") -> "HILKeyRing":
        return cls(active_key=key, active_key_id=key_id)

    @classmethod
    def from_environment(cls) -> Optional[HILKeyRing]:
        """
        Load HILKeyRing from explicit environment variables or mounted secret file.
        Returns None if no key is configured (never falls back to a hard-coded or random key).
        Raises HILConfigurationError if a configured key is empty, malformed, or weak.
        """
        key_file = os.environ.get("REVERSE_FORGE_HIL_KEY_FILE", "").strip()
        raw_key: Optional[str] = None
        if key_file:
            if not os.path.isfile(key_file):
                raise HILConfigurationError(f"Configured REVERSE_FORGE_HIL_KEY_FILE does not exist: {key_file}")
            with open(key_file, "r", encoding="utf-8") as f:
                raw_key = f.read().strip()
        elif "REVERSE_FORGE_HIL_KEY" in os.environ:
            raw_key = os.environ.get("REVERSE_FORGE_HIL_KEY", "")

        if raw_key is None:
            return None

        key_id = os.environ.get("REVERSE_FORGE_HIL_KEY_ID", "primary").strip() or "primary"
        extra_keys: Dict[str, Union[bytes, str]] = {}
        verify_json = os.environ.get("REVERSE_FORGE_HIL_VERIFY_KEYS_JSON", "").strip()
        if verify_json:
            try:
                parsed = json.loads(verify_json)
                if not isinstance(parsed, dict):
                    raise HILConfigurationError("REVERSE_FORGE_HIL_VERIFY_KEYS_JSON must be a JSON object")
                for k, v in parsed.items():
                    extra_keys[str(k)] = v
            except HILConfigurationError:
                raise
            except Exception as exc:
                raise HILConfigurationError(f"Malformed REVERSE_FORGE_HIL_VERIFY_KEYS_JSON: {exc}") from exc

        return cls(active_key=raw_key, active_key_id=key_id, verification_keys=extra_keys)

    def rotate_key(
        self,
        new_key_id: str,
        new_key: Union[bytes, str],
        retain_previous_for_verification: bool = True,
    ) -> None:
        """
        Rotate the active signing key to `new_key_id`.
        If `retain_previous_for_verification=True`, previously issued grants under the old key_id
        remain verifiable until they expire or `retire_key(old_key_id)` is called.
        """
        if not isinstance(new_key_id, str) or not _KEY_ID_RE.match(new_key_id):
            raise HILConfigurationError(f"Invalid new_key_id: {new_key_id!r}")
        validated_new = normalize_and_validate_signing_key(new_key, f"rotated_key[{new_key_id}]")
        with self._lock:
            if not retain_previous_for_verification:
                self._keys.clear()
            self._keys[new_key_id] = validated_new
            self.active_key_id = new_key_id
            self.active_key = validated_new

    def retire_key(self, key_id: str) -> None:
        """Remove a retired key from the verification keyring so grants signed with it are rejected."""
        with self._lock:
            if key_id == self.active_key_id:
                raise HILConfigurationError("Cannot retire the currently active signing key without rotating first")
            self._keys.pop(key_id, None)

    def get_verification_key(self, key_id: str) -> Optional[bytes]:
        with self._lock:
            return self._keys.get(key_id)

    def sign(self, message: bytes) -> Tuple[str, str]:
        with self._lock:
            sig = hmac.new(self.active_key, message, hashlib.sha256).hexdigest()
            return self.active_key_id, sig

    def verify(self, key_id: str, message: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or not signature:
            return False
        with self._lock:
            key = self._keys.get(key_id)
        if key is None:
            return False
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)


def canonicalize_parameters(params: Optional[Dict[str, Any]]) -> str:
    return ApprovalGrant.hash_parameters(params)


@dataclass(frozen=True)
class ApprovalGrant:
    """
    Cryptographically bound, single-use Human-in-the-Loop approval grant.
    Binds tightly to:
      (grant_id, key_id, tenant_id, operation, canonical target_path, target_sha256,
       canonical parameters_hash, authenticated approver_uid, approver_role, issued_at, expires_at).
    Issuance is strictly separated into `ApprovalIssuer.issue_grant()`.
    """
    grant_id: str
    operation: str
    target_sha256: str
    parameters_hash: str
    approver_uid: str
    issued_at: float
    expires_at: float
    signature: str
    tenant_id: str = "default_tenant"
    target_path: str = ""
    approver_role: str = "ANALYST"
    key_id: str = "primary"

    @classmethod
    def create(cls, *args: Any, **kwargs: Any) -> ApprovalGrant:
        """
        Direct unauthenticated grant creation via `ApprovalGrant.create()` is disabled in Phase 4.1.
        All grants must be issued through `ApprovalIssuer.issue_grant()` with an authenticated,
        authorized approver (`AuthUserContext`) and an explicit `HILKeyRing`.
        """
        raise AuthorizationDeniedError(
            AuthorizationDecision.DENIED_POLICY_VIOLATION,
            "Direct ApprovalGrant.create() is prohibited (Phase 4.1 separation of issuance and verification). "
            "Use ApprovalIssuer(key_ring).issue_grant(approver=..., operation=..., target_path=..., "
            "target_sha256=..., tenant_id=..., parameters=...).",
            {},
        )

    @staticmethod
    def hash_parameters(params: Optional[Dict[str, Any]]) -> str:
        """
        Deterministic, strict canonical JSON serialization and SHA-256 hash of parameters.
        Rejects non-dict parameter containers, non-string keys, non-finite floats, and arbitrary
        Python objects (never uses `default=str` or `str(sorted(...))` fallbacks).
        """
        if params is None:
            return hashlib.sha256(b"{}").hexdigest()
        if not isinstance(params, dict):
            raise TypeError(f"Approval parameters must be a dict or None, got {type(params).__name__}")
        _validate_strict_json_value(params, "$")
        canonical_json = json.dumps(
            params,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApprovalGrant:
        if not isinstance(data, dict):
            raise TypeError("ApprovalGrant payload must be a dict")
        return cls(
            grant_id=str(data["grant_id"]),
            operation=str(data["operation"]),
            target_sha256=str(data["target_sha256"]),
            parameters_hash=str(data["parameters_hash"]),
            approver_uid=str(data["approver_uid"]),
            issued_at=float(data["issued_at"]),
            expires_at=float(data["expires_at"]),
            signature=str(data["signature"]),
            tenant_id=str(data.get("tenant_id", "default_tenant")),
            target_path=str(data.get("target_path", "")),
            approver_role=str(data.get("approver_role", "ANALYST")),
            key_id=str(data.get("key_id", "primary")),
        )

    def is_valid_for(
        self,
        operation: Union[OperationType, str],
        target_sha256: str,
        parameters: Optional[Dict[str, Any]],
        signing_key: Optional[Union[bytes, str, HILKeyRing]] = None,
        target_tenant_id: Optional[str] = None,
        target_path: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Verify cryptographic signature, field bindings, clock skew, and TTL bounds.
        Fails closed if signing_key / HILKeyRing is missing or invalid.
        """
        try:
            op_enum = OperationType(operation) if isinstance(operation, str) else operation
            op_str = op_enum.value
        except Exception:
            return False, f"Invalid operation type: {operation!r}"

        # 1. Structural & identifier validation
        if not isinstance(self.grant_id, str) or not _GRANT_ID_RE.match(self.grant_id):
            return False, "Malformed grant_id in ApprovalGrant"
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.match(self.key_id):
            return False, "Malformed key_id in ApprovalGrant"
        if not isinstance(self.approver_uid, str) or not self.approver_uid.strip():
            return False, "Missing approver_uid in ApprovalGrant"
        if not isinstance(self.approver_role, str) or self.approver_role not in ("ANALYST", "LEAD_ARCHITECT"):
            return False, f"Unauthorized approver_role '{self.approver_role}' in ApprovalGrant"
        if op_enum == OperationType.DELETE_ARTIFACT and self.approver_role != UserRole.LEAD_ARCHITECT.value:
            return False, "DELETE_ARTIFACT grant requires LEAD_ARCHITECT approver"

        try:
            grant_sha = validate_strict_sha256(self.target_sha256)
            req_sha = validate_strict_sha256(target_sha256)
        except ValueError as err:
            return False, str(err)

        # 2. Timestamp & TTL bounds validation
        if (
            isinstance(self.issued_at, bool)
            or isinstance(self.expires_at, bool)
            or not isinstance(self.issued_at, (int, float))
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.issued_at)
            or not math.isfinite(self.expires_at)
        ):
            return False, "Malformed timestamp in ApprovalGrant"

        current_time = float(now if now is not None else time.time())
        ttl = float(self.expires_at) - float(self.issued_at)
        if ttl < MIN_GRANT_TTL_SECONDS or ttl > MAX_GRANT_TTL_SECONDS:
            return False, f"Approval grant TTL ({ttl:.2f}s) outside permitted bounds"
        if current_time > self.expires_at:
            return False, f"Approval grant expired (expired at {self.expires_at}, now {current_time})"
        if float(self.issued_at) > (current_time + MAX_CLOCK_SKEW_SECONDS):
            return False, "Approval grant has future issue timestamp outside clock-skew policy"

        # 3. Tenant binding check
        if target_tenant_id is not None and self.tenant_id != target_tenant_id:
            return False, f"Approval grant tenant mismatch ('{self.tenant_id}' != '{target_tenant_id}')"

        # 4. Operation binding check
        if self.operation != op_str:
            return False, f"Approval grant operation mismatch ('{self.operation}' != '{op_str}')"

        # 5. Canonical target path binding check
        if target_path is not None and self.target_path:
            try:
                canon_req_path = canonicalize_target_path(target_path)
            except ValueError as err:
                return False, str(err)
            if self.target_path != canon_req_path:
                return False, f"Approval grant target path mismatch ('{self.target_path}' != '{canon_req_path}')"

        # 6. Target SHA-256 binding check
        if grant_sha != req_sha:
            return False, f"Approval grant target mismatch ('{grant_sha}' != '{req_sha}')"

        # 7. Canonical parameter hash binding check
        try:
            current_param_hash = self.hash_parameters(parameters)
        except (TypeError, ValueError) as err:
            return False, f"Invalid operation parameters: {err}"
        if not hmac.compare_digest(self.parameters_hash.lower(), current_param_hash.lower()):
            return False, "Approval grant parameter hash mismatch (parameters modified after approval)"

        # 8. Resolve key ring & verify cryptographic signature (fail-closed if key missing/weak)
        try:
            key_ring = _resolve_key_ring(signing_key)
        except HILConfigurationError as err:
            return False, f"HIL key configuration invalid: {err}"

        if key_ring is None:
            return False, "HIL signing key configuration is missing (fail-closed)"

        msg = _canonical_grant_signing_payload(
            grant_id=self.grant_id,
            key_id=self.key_id,
            tenant_id=self.tenant_id,
            operation=self.operation,
            target_path=self.target_path,
            target_sha256=grant_sha,
            parameters_hash=self.parameters_hash.lower(),
            approver_uid=self.approver_uid,
            approver_role=self.approver_role,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        if not key_ring.verify(self.key_id, msg, self.signature):
            return False, "Approval grant signature invalid, unknown key_id, or forged"

        return True, "Valid"


def _resolve_key_ring(signing_key: Optional[Union[bytes, str, HILKeyRing]]) -> Optional[HILKeyRing]:
    if isinstance(signing_key, HILKeyRing):
        return signing_key
    if signing_key is not None:
        return HILKeyRing(active_key=signing_key)
    return HILKeyRing.from_environment()


class ApprovalIssuer:
    """
    Dedicated Human-in-the-Loop Approval Issuance Authority.
    Authenticates the approver, verifies RBAC role permissions and tenant ownership,
    validates all target/parameter bindings, and signs single-use ApprovalGrants using `HILKeyRing`.
    """

    APPROVER_ALLOWED_ROLES: Dict[OperationType, Set[UserRole]] = {
        OperationType.READ_METADATA: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.STATIC_ANALYSIS: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.EXPORT_REPORT: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.DYNAMIC_SANDBOX: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.NETWORK_ACCESS: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.MODIFY_ARTIFACT: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.REMEDIATION_PATCH: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.EXTERNAL_SERVICE: {UserRole.ANALYST, UserRole.LEAD_ARCHITECT},
        OperationType.DELETE_ARTIFACT: {UserRole.LEAD_ARCHITECT},
    }

    def __init__(self, key_ring: Optional[Union[HILKeyRing, bytes, str]] = None) -> None:
        resolved = _resolve_key_ring(key_ring)
        if resolved is None:
            raise HILConfigurationError("ApprovalIssuer requires a valid HILKeyRing or >=32-byte signing key")
        self.key_ring: HILKeyRing = resolved

    def issue_grant(
        self,
        approver: Optional[AuthUserContext],
        operation: Union[OperationType, str],
        target_path: str,
        target_sha256: str,
        tenant_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        ttl_seconds: float = 300.0,
        issued_at: Optional[float] = None,
        grant_id: Optional[str] = None,
    ) -> ApprovalGrant:
        """
        Authenticate `approver`, verify authorization for `operation` and `tenant_id`,
        validate inputs, and issue a cryptographically signed `ApprovalGrant`.
        """
        # 1. Authenticate approver identity & cryptographic verification seal
        if approver is None or not isinstance(approver, AuthUserContext) or not approver.is_cryptographically_verified():
            raise AuthorizationDeniedError(
                AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY,
                "Approver must be a cryptographically verified AuthUserContext to issue an ApprovalGrant",
                {},
            )

        # 2. Validate tenant & enforce approver tenant ownership
        clean_tenant = validate_tenant_id(tenant_id)
        if approver.tenant_id != clean_tenant:
            raise AuthorizationDeniedError(
                AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS,
                f"Approver from tenant '{approver.tenant_id}' cannot issue approval for tenant '{clean_tenant}'",
                {},
            )

        # 3. Validate operation & enforce approver role authorization
        op_enum = OperationType(operation) if isinstance(operation, str) else operation
        if not isinstance(op_enum, OperationType):
            raise ValueError(f"Invalid operation: {operation!r}")

        allowed_roles = self.APPROVER_ALLOWED_ROLES.get(op_enum, {UserRole.LEAD_ARCHITECT})
        if approver.role not in allowed_roles:
            raise AuthorizationDeniedError(
                AuthorizationDecision.DENIED_INSUFFICIENT_ROLE,
                f"Approver role '{approver.role.value}' is not authorized to issue approval for '{op_enum.value}'",
                {},
            )

        # 4. Validate target path, target SHA-256, TTL, and parameters
        canon_path = canonicalize_target_path(target_path)
        clean_sha = validate_strict_sha256(target_sha256)

        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or not math.isfinite(ttl_seconds):
            raise ValueError("ttl_seconds must be a finite number")
        if ttl_seconds < MIN_GRANT_TTL_SECONDS or ttl_seconds > MAX_GRANT_TTL_SECONDS:
            raise ValueError(
                f"ttl_seconds ({ttl_seconds}) must be between {MIN_GRANT_TTL_SECONDS} and {MAX_GRANT_TTL_SECONDS}"
            )

        param_hash = ApprovalGrant.hash_parameters(parameters)
        gid = grant_id if grant_id is not None else uuid.uuid4().hex
        if not isinstance(gid, str) or not _GRANT_ID_RE.match(gid):
            raise ValueError(f"Invalid grant_id format: {gid!r}")

        now_ts = round(float(issued_at if issued_at is not None else time.time()), 6)
        exp_ts = round(now_ts + float(ttl_seconds), 6)

        msg = _canonical_grant_signing_payload(
            grant_id=gid,
            key_id=self.key_ring.active_key_id,
            tenant_id=clean_tenant,
            operation=op_enum.value,
            target_path=canon_path,
            target_sha256=clean_sha,
            parameters_hash=param_hash,
            approver_uid=approver.uid,
            approver_role=approver.role.value,
            issued_at=now_ts,
            expires_at=exp_ts,
        )
        kid, sig = self.key_ring.sign(msg)

        return ApprovalGrant(
            grant_id=gid,
            operation=op_enum.value,
            target_sha256=clean_sha,
            parameters_hash=param_hash,
            approver_uid=approver.uid,
            issued_at=now_ts,
            expires_at=exp_ts,
            signature=sig,
            tenant_id=clean_tenant,
            target_path=canon_path,
            approver_role=approver.role.value,
            key_id=kid,
        )


# ==============================================================================
# SECTION 2: ATOMIC SINGLE-USE GRANT CONSUMPTION STORES (Phase 4.1 §3)
# ==============================================================================

class GrantConsumptionStore(abc.ABC):
    """
    Abstract atomic single-use grant consumption store.
    Guarantees that each `grant_id` is consumed at most once across all workers sharing
    the store, survives process restarts, binds consumption to tenant/security context,
    and raises `GrantStorageError` on backend failures so callers fail closed.
    """

    @abc.abstractmethod
    def consume_grant_atomic(
        self,
        grant: ApprovalGrant,
        tenant_id: str,
        operation: str,
        target_sha256: str,
        now: Optional[float] = None,
    ) -> bool:
        """
        Atomically mark `grant` as consumed.
        Returns True iff the grant was not previously consumed and is within validity window.
        Returns False if the grant was already consumed or is expired.
        Raises GrantStorageError if underlying storage fails.
        """
        ...

    @abc.abstractmethod
    def is_consumed(self, grant_id: str) -> bool:
        """Return True if `grant_id` has been consumed."""
        ...

    @abc.abstractmethod
    def cleanup_expired_records(self, retention_horizon_seconds: float = 3600.0, now: Optional[float] = None) -> int:
        """
        Delete consumption records whose grant expiration timestamp is strictly older than
        `now - MAX_CLOCK_SKEW_SECONDS - retention_horizon_seconds`.
        Because expired grants are always rejected prior to consumption lookup, pruning
        records after `expires_at + MAX_CLOCK_SKEW_SECONDS` can never re-enable a consumed grant.
        """
        ...


class SQLiteAtomicGrantConsumptionStore(GrantConsumptionStore):
    """
    Cross-process, restart-persistent atomic grant consumption store backed by SQLite
    with `BEGIN IMMEDIATE` transactions and `PRIMARY KEY (grant_id)` uniqueness enforcement.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        default_path = os.environ.get(
            "REVERSE_FORGE_HIL_DB_PATH",
            os.path.join(tempfile.gettempdir(), "reverse_forge_hil_grants.sqlite"),
        )
        self.db_path = os.path.abspath(db_path or default_path)
        self._lock = threading.RLock()
        self._initialized = False
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            try:
                parent = os.path.dirname(self.db_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                conn = sqlite3.connect(self.db_path, timeout=15.0, isolation_level=None)
                try:
                    conn.execute("PRAGMA journal_mode=WAL")
                    conn.execute("PRAGMA synchronous=FULL")
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS hil_consumed_grants ("
                        "grant_id TEXT PRIMARY KEY, "
                        "tenant_id TEXT NOT NULL, "
                        "operation TEXT NOT NULL, "
                        "target_sha256 TEXT NOT NULL, "
                        "target_path TEXT NOT NULL, "
                        "approver_uid TEXT NOT NULL, "
                        "issued_at REAL NOT NULL, "
                        "expires_at REAL NOT NULL, "
                        "consumed_at REAL NOT NULL, "
                        "signature_sha256 TEXT NOT NULL)"
                    )
                    self._initialized = True
                finally:
                    conn.close()
            except Exception as exc:
                raise GrantStorageError(f"Failed to initialize SQLite grant consumption store: {exc}") from exc

    def consume_grant_atomic(
        self,
        grant: ApprovalGrant,
        tenant_id: str,
        operation: str,
        target_sha256: str,
        now: Optional[float] = None,
    ) -> bool:
        current_time = float(now if now is not None else time.time())
        if current_time > grant.expires_at:
            return False
        if grant.issued_at > (current_time + MAX_CLOCK_SKEW_SECONDS):
            return False
        if grant.tenant_id != tenant_id or grant.operation != operation or grant.target_sha256.lower() != target_sha256.lower():
            return False

        sig_hash = hashlib.sha256(grant.signature.encode("utf-8")).hexdigest()
        with self._lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=15.0, isolation_level=None)
            except Exception as exc:
                raise GrantStorageError(f"Unable to open grant consumption database: {exc}") from exc

            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO hil_consumed_grants ("
                    "grant_id, tenant_id, operation, target_sha256, target_path, "
                    "approver_uid, issued_at, expires_at, consumed_at, signature_sha256"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        grant.grant_id,
                        tenant_id,
                        operation,
                        target_sha256.lower(),
                        grant.target_path,
                        grant.approver_uid,
                        float(grant.issued_at),
                        float(grant.expires_at),
                        current_time,
                        sig_hash,
                    ),
                )
                conn.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                return False
            except Exception as exc:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise GrantStorageError(f"Atomic grant consumption failed due to storage error: {exc}") from exc
            finally:
                conn.close()

    def is_consumed(self, grant_id: str) -> bool:
        with self._lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=10.0)
                try:
                    cur = conn.execute(
                        "SELECT 1 FROM hil_consumed_grants WHERE grant_id = ? LIMIT 1",
                        (grant_id,),
                    )
                    return cur.fetchone() is not None
                finally:
                    conn.close()
            except Exception as exc:
                raise GrantStorageError(f"Failed to query grant consumption state: {exc}") from exc

    def cleanup_expired_records(self, retention_horizon_seconds: float = 3600.0, now: Optional[float] = None) -> int:
        if retention_horizon_seconds < 0:
            raise ValueError("retention_horizon_seconds must be >= 0 to prevent re-enabling unexpired grants")
        current_time = float(now if now is not None else time.time())
        cutoff_expires_at = current_time - MAX_CLOCK_SKEW_SECONDS - float(retention_horizon_seconds)
        with self._lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    cur = conn.execute(
                        "DELETE FROM hil_consumed_grants WHERE expires_at < ?",
                        (cutoff_expires_at,),
                    )
                    deleted = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0
                    conn.execute("COMMIT")
                    return deleted
                except Exception:
                    try:
                        conn.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise
                finally:
                    conn.close()
            except Exception as exc:
                raise GrantStorageError(f"Failed to clean up expired grant records: {exc}") from exc


class FirestoreTransactionalGrantConsumptionStore(GrantConsumptionStore):
    """
    Cloud Firestore atomic grant consumption store using document `create()` precondition
    (`exists == False`) on collection `hil_consumed_grants/{grant_id}`.
    """

    def __init__(self, firestore_client: Any, collection_name: str = "hil_consumed_grants") -> None:
        if firestore_client is None:
            raise GrantStorageError("FirestoreTransactionalGrantConsumptionStore requires a valid firestore_client")
        self._db = firestore_client
        self.collection_name = validate_document_id(collection_name, "collection_name")

    def consume_grant_atomic(
        self,
        grant: ApprovalGrant,
        tenant_id: str,
        operation: str,
        target_sha256: str,
        now: Optional[float] = None,
    ) -> bool:
        current_time = float(now if now is not None else time.time())
        if current_time > grant.expires_at or grant.issued_at > (current_time + MAX_CLOCK_SKEW_SECONDS):
            return False
        if grant.tenant_id != tenant_id or grant.operation != operation or grant.target_sha256.lower() != target_sha256.lower():
            return False

        gid = validate_document_id(grant.grant_id, "grant_id")
        record = {
            "grant_id": gid,
            "tenant_id": tenant_id,
            "operation": operation,
            "target_sha256": target_sha256.lower(),
            "target_path": grant.target_path,
            "approver_uid": grant.approver_uid,
            "issued_at": float(grant.issued_at),
            "expires_at": float(grant.expires_at),
            "consumed_at": current_time,
            "signature_sha256": hashlib.sha256(grant.signature.encode("utf-8")).hexdigest(),
        }
        try:
            doc_ref = self._db.collection(self.collection_name).document(gid)
            doc_ref.create(record)
            return True
        except Exception as exc:
            cls_name = exc.__class__.__name__.lower()
            code = getattr(exc, "code", None)
            code_val = code() if callable(code) else code
            if "alreadyexists" in cls_name or "already_exists" in cls_name or code_val in (409, "ALREADY_EXISTS"):
                return False
            raise GrantStorageError(f"Firestore atomic grant consumption failed: {exc.__class__.__name__}") from exc

    def is_consumed(self, grant_id: str) -> bool:
        gid = validate_document_id(grant_id, "grant_id")
        try:
            snap = self._db.collection(self.collection_name).document(gid).get()
            return bool(snap.exists)
        except Exception as exc:
            raise GrantStorageError(f"Firestore grant consumption check failed: {exc.__class__.__name__}") from exc

    def cleanup_expired_records(self, retention_horizon_seconds: float = 3600.0, now: Optional[float] = None) -> int:
        if retention_horizon_seconds < 0:
            raise ValueError("retention_horizon_seconds must be >= 0")
        current_time = float(now if now is not None else time.time())
        cutoff = current_time - MAX_CLOCK_SKEW_SECONDS - float(retention_horizon_seconds)
        try:
            col = self._db.collection(self.collection_name)
            deleted = 0
            for doc in col.stream():
                data = doc.to_dict() or {}
                if float(data.get("expires_at", float("inf"))) < cutoff:
                    doc.reference.delete()
                    deleted += 1
            return deleted
        except Exception as exc:
            raise GrantStorageError(f"Firestore expired grant cleanup failed: {exc.__class__.__name__}") from exc


# ==============================================================================
# SECTION 3: CENTRAL AUTHORIZATION BOUNDARY (Phase 4 & Phase 4.1 Hardened)
# ==============================================================================

class CentralAuthorizationBoundary:
    """
    Unified, fail-closed authorization engine for all reverse engineering operations.
    Enforces cryptographic principal verification, RBAC, tenant isolation, scope boundaries,
    TOCTOU target hash revalidation, and atomic single-use human-in-the-loop approval.
    """

    MANDATORY_HIL_OPERATIONS: Set[OperationType] = {
        OperationType.DYNAMIC_SANDBOX,
        OperationType.NETWORK_ACCESS,
        OperationType.DELETE_ARTIFACT,
        OperationType.MODIFY_ARTIFACT,
    }

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

    def __init__(
        self,
        signing_key: Optional[Union[bytes, str, HILKeyRing]] = None,
        consumption_store: Optional[GrantConsumptionStore] = None,
        verify_target_on_disk: bool = True,
    ):
        # Never fall back to a hard-coded or process-local random key.
        # If signing_key is explicitly passed, validate it immediately; otherwise resolve from environment on demand.
        self._configured_signing_key: Optional[Union[bytes, str, HILKeyRing]] = (
            _resolve_key_ring(signing_key) if signing_key is not None else None
        )
        self.consumption_store: GrantConsumptionStore = (
            consumption_store if consumption_store is not None else SQLiteAtomicGrantConsumptionStore()
        )
        self.verify_target_on_disk = bool(verify_target_on_disk)
        self._audit_log: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def _get_active_key_ring(self) -> Optional[HILKeyRing]:
        if self._configured_signing_key is not None:
            return _resolve_key_ring(self._configured_signing_key)
        return HILKeyRing.from_environment()

    @property
    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._audit_log)

    @staticmethod
    def _verify_on_disk_sha256(target_path: str, expected_sha256: str) -> Tuple[bool, str]:
        """Recompute SHA-256 of `target_path` immediately before execution to prevent TOCTOU swaps."""
        if not target_path or not os.path.isfile(target_path):
            return True, "No regular file at target_path"
        if not _STRICT_SHA256_RE.match(expected_sha256 or ""):
            return False, f"Invalid target_sha256 format '{expected_sha256}' for existing file '{target_path}'"
        try:
            real_target = os.path.realpath(os.path.abspath(target_path))
            hasher = hashlib.sha256()
            with open(real_target, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            actual = hasher.hexdigest().lower()
            if actual != expected_sha256.lower():
                return (
                    False,
                    f"TOCTOU target integrity mismatch: disk file SHA-256 '{actual}' != expected '{expected_sha256.lower()}'",
                )
            return True, "Verified"
        except Exception as exc:
            return False, f"Failed to verify target file integrity on disk: {exc}"

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
        verify_target_on_disk: Optional[bool] = None,
    ) -> Tuple[bool, AuthorizationDecision, str, Optional[ApprovalGrant]]:
        """
        Evaluates the authorization policy for a requested operation immediately before execution.
        Returns: (permitted, decision, reason, grant_consumed)
        """
        try:
            op = OperationType(operation) if isinstance(operation, str) else operation
        except Exception:
            reason = f"Unknown or unsupported operation type: {operation!r}"
            self._record_audit(principal, OperationType.READ_METADATA, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_POLICY_VIOLATION, reason)
            return False, AuthorizationDecision.DENIED_POLICY_VIOLATION, reason, None

        params = parameters if parameters is not None else {}

        # 1. Principal & Unforgeable Identity Seal Verification
        if (
            principal is None
            or not isinstance(principal, AuthUserContext)
            or not principal.is_cryptographically_verified()
        ):
            reason = "Unverified, missing, or unsealed principal identity. Privileged operations require cryptographically verified credentials."
            self._record_audit(principal, op, target_sha256, target_tenant_id, False, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY, reason)
            return False, AuthorizationDecision.DENIED_UNVERIFIED_IDENTITY, reason, None

        # 2. Tenant Validation & Ownership Verification
        try:
            clean_target_tenant = validate_tenant_id(target_tenant_id)
            clean_principal_tenant = validate_tenant_id(principal.tenant_id)
        except ValueError as err:
            reason = f"Invalid tenant context: {err}"
            self._record_audit(principal, op, target_sha256, str(target_tenant_id), False, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS, reason)
            return False, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS, reason, None

        if clean_principal_tenant != clean_target_tenant:
            reason = f"Cross-tenant access prohibited: principal tenant '{clean_principal_tenant}' != target tenant '{clean_target_tenant}'"
            self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS, reason)
            return False, AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS, reason, None

        # 3. Role-Based Access Control (RBAC)
        allowed_roles = self.ROLE_PERMISSIONS.get(op, {UserRole.LEAD_ARCHITECT})
        if principal.role not in allowed_roles:
            reason = f"Role '{principal.role.value}' lacks permission for operation '{op.value}'. Required: {[r.value for r in allowed_roles]}"
            self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE, reason)
            return False, AuthorizationDecision.DENIED_INSUFFICIENT_ROLE, reason, None

        # 4. Target Path Canonicalization & Scope Ledger Policy Check
        try:
            canon_target_path = canonicalize_target_path(target_path)
        except ValueError as err:
            reason = f"Invalid target path: {err}"
            self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_OUT_OF_SCOPE, reason)
            return False, AuthorizationDecision.DENIED_OUT_OF_SCOPE, reason, None

        if scope_ledger is not None:
            action_perm = self.ACTION_PERMISSION_MAP.get(op, ActionPermission.STATIC_ANALYSIS)
            if not scope_ledger.is_authorized(target_path, action=action_perm):
                reason = f"Scope ledger policy denied action '{action_perm.value}' for target '{target_path}'"
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_OUT_OF_SCOPE, reason)
                return False, AuthorizationDecision.DENIED_OUT_OF_SCOPE, reason, None

        # 5. TOCTOU Target Hash Revalidation
        check_disk = self.verify_target_on_disk if verify_target_on_disk is None else bool(verify_target_on_disk)
        if check_disk and os.path.isfile(canon_target_path) and _STRICT_SHA256_RE.match(target_sha256 or ""):
            disk_ok, disk_reason = self._verify_on_disk_sha256(canon_target_path, target_sha256)
            if not disk_ok:
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH, disk_reason)
                return False, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH, disk_reason, None

        # 6. Mandatory Human-In-The-Loop (HIL) Evaluation
        is_mandatory_hil = op in self.MANDATORY_HIL_OPERATIONS
        if is_mandatory_hil:
            requires_hil = True
        elif autonomy_level <= 0:
            requires_hil = True  # MANUAL: every action requires sign-off
        elif autonomy_level == 1:
            requires_hil = op not in {OperationType.READ_METADATA, OperationType.STATIC_ANALYSIS, OperationType.EXPORT_REPORT}
        else:
            requires_hil = False

        active_grant = approval_grant

        if requires_hil:
            callback_res: Any = active_grant
            if active_grant is None:
                if hil_callback is None:
                    reason = f"Operation '{op.value}' strictly requires human approval, but no ApprovalGrant or HIL callback was provided (fail-closed)"
                    self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason)
                    return False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason, None

                prompt = f"Approve execution of '{op.value}' on target SHA-256 {target_sha256[:16]}...?"
                context = {
                    "operation": op.value,
                    "target_path": canon_target_path,
                    "target_sha256": target_sha256.lower(),
                    "tenant_id": clean_target_tenant,
                    "principal_uid": principal.uid,
                    "parameters": params,
                }

                try:
                    callback_res = hil_callback(prompt, context)
                except Exception as exc:
                    reason = f"HIL approval callback raised exception: {type(exc).__name__} (fail-closed)"
                    self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_CALLBACK_FAILED, reason)
                    return False, AuthorizationDecision.DENIED_HIL_CALLBACK_FAILED, reason, None

                if not isinstance(callback_res, ApprovalGrant) and callback_res is not True:
                    reason = f"Operator denied approval for operation '{op.value}'"
                    self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason)
                    return False, AuthorizationDecision.DENIED_HIL_APPROVAL_REQUIRED, reason, None

            # Resolve and validate HIL signing/verification keyring (fail-closed if missing/weak)
            try:
                key_ring = self._get_active_key_ring()
            except HILConfigurationError as err:
                reason = f"HIL signing configuration error: {err} (fail-closed)"
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_CONFIG_INVALID, reason)
                return False, AuthorizationDecision.DENIED_HIL_CONFIG_INVALID, reason, None

            if key_ring is None:
                reason = f"Operation '{op.value}' requires HIL approval, but no HIL signing key is configured (fail-closed)"
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_CONFIG_INVALID, reason)
                return False, AuthorizationDecision.DENIED_HIL_CONFIG_INVALID, reason, None

            if not _STRICT_SHA256_RE.match(target_sha256 or ""):
                reason = f"Sensitive HIL operation '{op.value}' requires a valid 64-char SHA-256 digest"
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH, reason)
                return False, AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH, reason, None

            if active_grant is None:
                if isinstance(callback_res, ApprovalGrant):
                    active_grant = callback_res
                elif callback_res is True:
                    # Callback approved interactively: issue bound grant through ApprovalIssuer
                    try:
                        issuer = ApprovalIssuer(key_ring=key_ring)
                        active_grant = issuer.issue_grant(
                            approver=principal,
                            operation=op,
                            target_path=canon_target_path,
                            target_sha256=target_sha256.lower(),
                            tenant_id=clean_target_tenant,
                            parameters=params,
                            ttl_seconds=300.0,
                        )
                    except AuthorizationDeniedError as err:
                        self._record_audit(principal, op, target_sha256, clean_target_tenant, False, err.decision, err.reason)
                        return False, err.decision, err.reason, None
                    except Exception as err:
                        reason = f"HIL grant issuance failed: {err}"
                        self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_POLICY_VIOLATION, reason)
                        return False, AuthorizationDecision.DENIED_POLICY_VIOLATION, reason, None

            # Validate cryptographic grant bindings, expiry, clock skew, tenant, target_path, target_sha256, parameters, and signature
            valid, err = active_grant.is_valid_for(
                operation=op,
                target_sha256=target_sha256,
                parameters=params,
                signing_key=key_ring,
                target_tenant_id=clean_target_tenant,
                target_path=canon_target_path,
            )
            if not valid:
                err_l = err.lower()
                if "expired" in err_l or "future issue" in err_l or "ttl" in err_l:
                    dec = AuthorizationDecision.DENIED_HIL_APPROVAL_STALE
                elif "tenant mismatch" in err_l:
                    dec = AuthorizationDecision.DENIED_CROSS_TENANT_ACCESS
                elif "target mismatch" in err_l or "target path mismatch" in err_l or "target_sha256" in err_l:
                    dec = AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH
                elif "parameter" in err_l:
                    dec = AuthorizationDecision.DENIED_HIL_PARAMETER_MISMATCH
                elif "key configuration" in err_l or "signing key" in err_l:
                    dec = AuthorizationDecision.DENIED_HIL_CONFIG_INVALID
                else:
                    dec = AuthorizationDecision.DENIED_POLICY_VIOLATION
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, dec, err, grant_id=active_grant.grant_id)
                return False, dec, err, None

            # Atomically consume single-use grant in persistent/shared store
            try:
                consumed_ok = self.consumption_store.consume_grant_atomic(
                    grant=active_grant,
                    tenant_id=clean_target_tenant,
                    operation=op.value,
                    target_sha256=target_sha256.lower(),
                )
            except GrantStorageError as exc:
                reason = f"HIL replay-prevention storage failure: {exc} (fail-closed)"
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_STORAGE_FAILURE, reason, grant_id=active_grant.grant_id)
                return False, AuthorizationDecision.DENIED_STORAGE_FAILURE, reason, None

            if not consumed_ok:
                reason = f"Approval grant '{active_grant.grant_id}' has already been consumed or expired (atomic replay prevention)"
                self._record_audit(principal, op, target_sha256, clean_target_tenant, False, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE, reason, grant_id=active_grant.grant_id)
                return False, AuthorizationDecision.DENIED_HIL_APPROVAL_STALE, reason, None

        # 7. Permit operation
        self._record_audit(
            principal,
            op,
            target_sha256,
            clean_target_tenant,
            True,
            AuthorizationDecision.PERMITTED,
            "Authorized",
            grant_id=active_grant.grant_id if active_grant else None,
        )
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
    ) -> Optional[ApprovalGrant]:
        """
        Enforces authorization policy. Raises AuthorizationDeniedError immediately if denied.
        Never mints synthetic grants when no HIL grant was used.
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
            with self._lock:
                latest_audit = self._audit_log[-1] if self._audit_log else {}
            raise AuthorizationDeniedError(decision, reason, latest_audit)
        return grant

    def _record_audit(
        self,
        principal: Optional[AuthUserContext],
        operation: OperationType,
        target_sha256: str,
        tenant_id: str,
        permitted: bool,
        decision: AuthorizationDecision,
        reason: str,
        grant_id: Optional[str] = None,
    ) -> None:
        safe_sha = (target_sha256 or "")[:64]
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_uid": principal.uid if isinstance(principal, AuthUserContext) else "unauthenticated",
            "principal_role": principal.role.value if isinstance(principal, AuthUserContext) and isinstance(principal.role, UserRole) else "NONE",
            "principal_verified": principal.is_cryptographically_verified() if isinstance(principal, AuthUserContext) else False,
            "principal_tenant": principal.tenant_id if isinstance(principal, AuthUserContext) else "NONE",
            "target_tenant": str(tenant_id),
            "target_sha256": safe_sha,
            "operation": operation.value,
            "grant_id": grant_id,
            "permitted": permitted,
            "decision": decision.value,
            "reason": reason,
        }
        with self._lock:
            self._audit_log.append(entry)
            logger.info(
                "AUTH_DECISION: %s op=%s target=%s permitted=%s grant=%s reason=%s",
                decision.value,
                operation.value,
                safe_sha[:12],
                permitted,
                grant_id or "none",
                reason,
            )


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


def reset_authorization_boundary(
    signing_key: Optional[Union[bytes, str, HILKeyRing]] = None,
    consumption_store: Optional[GrantConsumptionStore] = None,
) -> CentralAuthorizationBoundary:
    """Reconfigure and return the global CentralAuthorizationBoundary instance."""
    global _global_boundary
    with _boundary_lock:
        _global_boundary = CentralAuthorizationBoundary(
            signing_key=signing_key,
            consumption_store=consumption_store,
        )
        return _global_boundary
