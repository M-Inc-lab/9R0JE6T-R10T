# 9R0JE6T-R10T Security Architecture & Threat Model

**Document Version:** 4.1.0  
**Phase:** Phase 4.1 — Trust Boundary Closure, Security Remediation & Independent Verification  
**Date:** 2026-10-27  

---

## 1. Principles of Security Architecture
The `R3V3R53//F0RG3` reverse engineering platform adheres to a strict **fail-closed**, **least-privilege**, and **evidence-driven** security foundation:
1. **Zero Unverified Trust**: Tokens, binary payloads, external libraries, and operator inputs are treated as untrusted until verified cryptographically or validated against explicit bounds.
2. **Fail-Closed Policy Enforcement**: Any missing credential, absent or weak HIL signing key, absent authorization callback, storage failure, malformed header, or unexpected binary format results in immediate, explicit denial with a structured diagnostic state.
3. **No Autonomy Bypass**: Operator autonomy configuration dictates task automation within permitted bounds, but cannot override mandatory safety, boundary, or execution policy.
4. **Honest Persistence & Capability Separation**: Local in-memory simulations, in-memory CPU emulation, heuristic/concolic hypotheses, and external host tool integrations (`Ghidra`, `IDA`, `Rizin`, `Cutter`) are strictly demarcated from confirmed vulnerabilities and live cloud infrastructure.
5. **Zero Side-Effects on Denial**: Denied operations are aborted immediately before touching disk, altering artifacts, launching processes, or performing network operations.

---

## 2. Authentication & Identity Provider (IdP) Verification

### Token Verification Flow (`reverse_forge/firebase_sync.py`)
Token authentication is implemented via `FirebaseAuthManager`:
- **Cryptographic Signature & Algorithm Compatibility**: Defaults explicitly to `["RS256"]` (Google/Firebase IdP standard) and enforces `validate_key_algorithm_compatibility()` to block algorithm confusion (such as using an RSA/EC public key as an HMAC `HS256` secret) and `alg: none`.
- **Unforgeable Identity Seal (`AuthUserContext`)**: Verified contexts are issued exclusively by `FirebaseAuthManager` with an HMAC-SHA256 `_verification_seal` bound to `(uid, email, role, tenant_id)`. Direct construction `AuthUserContext(..., is_verified=True)` or post-construction attribute mutation invalidates the seal (`is_cryptographically_verified() == False`).
- **Strict Claim & Role Validation**:
  - `exp`, `nbf`, and `iat`: Must be numeric timestamps (`bool` rejected); expired, premature (`nbf`), and future-issued (`iat`) tokens outside clock skew (`5.0s`) are rejected.
  - `iss` and `aud`: Verified against the configured trusted IdP issuer and project audience.
  - `sub` and `jti`: Must be non-empty strings.
  - `role`: Validated strictly via `FirebaseAuthManager.resolve_role()`. Unrecognized or malformed role values raise `ValueError` and reject the token (never defaulting unknown roles to `ANALYST`).
  - `tenant_id`: Validated against `validate_tenant_id()`, `trusted_tenants`, and server-side `tenant_membership_policy`.
- **Revocation Persistence (`SharedRevocationStore`)**: Supports both process-local denylists and shared SQLite WAL persistence (`FIREBASE_REVOCATION_DB_PATH` / `SharedRevocationStore`) so token (`jti`) and user (`uid`) revocations survive restarts and apply across workers.

### Production vs Development Isolation
- **Mock Authentication Guard**: Mock authentication tokens (`mock-token-*`, `dev-token-*`) are permitted **only** when `allow_dev_mock=True` and `REVERSE_FORGE_ENV != "production"`, and always receive unverified `UserRole.VIEWER` contexts (`is_verified=False`).
- In `REVERSE_FORGE_ENV=production`, mock tokens and missing verification configurations fail closed immediately (`None`).

---

## 3. Centralized Execution Authorization, HIL Key Management & Single-Use Consumption

### CentralAuthorizationBoundary (`reverse_forge/authorization.py`)
All routes into sensitive operations (`PipelineStateMachine` stages `0..11`, `GUIWorkbenchHandler` endpoints, `InvestigationWorkflowEngine`) are evaluated immediately before execution side-effects occur:
1. **Cryptographic Principal Seal**: `principal.is_cryptographically_verified()` must be `True`.
2. **Tenant Ownership**: `principal.tenant_id == target_tenant_id`.
3. **Role-Based Access Control**:
   - `DELETE_ARTIFACT`: Requires `LEAD_ARCHITECT`.
   - `MODIFY_ARTIFACT`, `REMEDIATION_PATCH`, `DYNAMIC_SANDBOX`, `NETWORK_ACCESS`, `EXTERNAL_SERVICE`: Requires `ANALYST` or `LEAD_ARCHITECT`.
   - `VIEWER`: Strictly read-only (`READ_METADATA`, `STATIC_ANALYSIS`, `EXPORT_REPORT`).
4. **Scope Policy & TOCTOU Revalidation**: `ScopeLedger.is_authorized` must permit the canonical realpath and action, and `_verify_on_disk_sha256` recomputes the on-disk file SHA-256 immediately before execution.
5. **Separated HIL Issuance (`ApprovalIssuer`) & Key Rotation (`HILKeyRing`)**:
   - No default or hard-coded signing key exists. Missing, empty, or weak (<32-byte or <8 distinct byte) keys fail closed (`DENIED_HIL_CONFIG_INVALID`).
   - `ApprovalGrant.create()` is disabled; only `ApprovalIssuer(key_ring).issue_grant(...)` can issue grants after authenticating and authorizing the approver.
   - Each grant binds `(grant_id, key_id, tenant_id, operation, canonical target_path, target_sha256, canonical parameters_hash, approver_uid, approver_role, issued_at, expires_at)` using strict canonical JSON (`allow_nan=False`, no `default=str`).
6. **Atomic Single-Use Consumption (`GrantConsumptionStore`)**:
   - `SQLiteAtomicGrantConsumptionStore` (SQLite WAL `BEGIN IMMEDIATE`) and `FirestoreTransactionalGrantConsumptionStore` (Firestore `create()` precondition) ensure each grant is consumed at most once across threads, processes, and restarts. Storage errors fail closed (`DENIED_STORAGE_FAILURE`).

---

## 4. Multi-Tenant Cloud Persistence (`reverse_forge/firebase_sync.py`)

- **Principal-Derived Tenant Scoping**: `FirebaseSyncManager` requires a verified `AuthUserContext` and derives tenant scope from `user.tenant_id`, raising `PersistencePermissionError` if a caller supplies a mismatched `tenant_id`.
- **Strict Path & Identifier Validation**: `validate_tenant_id`, `validate_artifact_sha256`, `validate_document_id`, and `validate_storage_blob_path` reject `..` traversal, path separators in IDs, and URI schemes (`gs://`, `http://`, `file://`).
- **Typed Error Separation**: `ProductionFirestoreStorageAdapter` verifies document `tenant_id` ownership on reads/writes and distinguishes missing documents (`None`) from permission denials (`PersistencePermissionError`) and backend outages (`PersistenceUnavailableError`).

---

## 5. Native Execution & Toolchain Cache Invalidation (`reverse_forge/native_rust_bridge.py`)

1. **Toolchain & Build Fingerprinting**: Native shared objects are cached with SHA-256 fingerprints incorporating `Cargo.toml`, `c_fallback_bridge.c`, `standalone_cli.c`, `src/*.rs`, compiler versions, build flags, host platform, and ABI version (`v2`).
2. **ABI Verification Vectors**: Validates FLIRT CRC-16 (`0x906E`), empty-buffer Shannon entropy (`0.0`), and FNV1a-64 (`0xf9e6e6ef197c2b25`) before activating any native library.
