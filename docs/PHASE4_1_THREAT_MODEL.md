# R3V3R53//F0RG3 — Phase 4.1 Threat Model & Trust Boundary Architecture

**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Document Version:** 4.1.0  
**Date:** 2026-10-27  

---

## 1. Trust Boundaries

The `R3V3R53//F0RG3` platform operates across five explicit trust boundaries:

1. **Boundary TB-1: External Caller / HTTP Client <-> Authentication Authority (`FirebaseAuthManager`)**
   - **Untrusted Inputs:** HTTP `Authorization: Bearer <token>` headers, `Origin` headers, query parameters, JSON request bodies, and CLI flags.
   - **Enforcement:**
     - `FirebaseAuthManager.verify_bearer_token()` verifies 3-segment JWT structure, algorithm allowlist (`["RS256"]` by default), key-algorithm compatibility (`validate_key_algorithm_compatibility` preventing RSA/EC public keys from being used as HMAC secrets), cryptographic signature, `exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`, revocation state (`SharedRevocationStore`), strict role resolution (`resolve_role` rejecting unknown roles), and server-side tenant membership (`tenant_membership_policy` / `trusted_tenants`).
     - Verified principals receive an unforgeable per-process HMAC `_verification_seal` via `_create_sealed_user_context()`. Manually constructing `AuthUserContext(..., is_verified=True)` or mutating fields (`role`, `tenant_id`, `uid`) after construction invalidates the seal (`is_cryptographically_verified() == False`).

2. **Boundary TB-2: Authenticated Principal <-> Central Execution Authorization Boundary (`CentralAuthorizationBoundary`)**
   - **Untrusted Inputs:** Requested operation (`OperationType`), target binary path, claimed `target_sha256`, `target_tenant_id`, operation `parameters`, and optional `ApprovalGrant`.
   - **Enforcement:**
     - Verifies `principal.is_cryptographically_verified()`.
     - Validates `target_tenant_id` format and enforces `principal.tenant_id == target_tenant_id`.
     - Enforces least-privilege RBAC (`VIEWER` read-only; `ANALYST` static/dynamic/modify/remediate; `LEAD_ARCHITECT` required for `DELETE_ARTIFACT`).
     - Enforces `ScopeLedger.is_authorized(target_path, action)` on the canonicalized realpath.
     - Recomputes the on-disk file SHA-256 (`_verify_on_disk_sha256`) immediately before execution to defeat Time-of-Check to Time-of-Use (TOCTOU) binary swap attacks.
     - Enforces mandatory Human-in-the-Loop (`MANDATORY_HIL_OPERATIONS`: `DYNAMIC_SANDBOX`, `NETWORK_ACCESS`, `DELETE_ARTIFACT`, `MODIFY_ARTIFACT`) regardless of `AutonomyLevel`.

3. **Boundary TB-3: HIL Approval Issuance (`ApprovalIssuer`) <-> Single-Use Verification & Consumption (`ApprovalGrant`, `GrantConsumptionStore`)**
   - **Untrusted Inputs:** Operator callback responses, serialized `ApprovalGrant` dictionaries (`X-HIL-Approval-Grant` header or JSON body), and concurrent replay attempts.
   - **Enforcement:**
     - Separation of privileges: `ApprovalGrant.create()` is disabled. Only `ApprovalIssuer(key_ring).issue_grant(...)` can sign a new grant after verifying the approver's sealed `AuthUserContext`, RBAC role for the requested operation, tenant ownership, canonical target path, 64-char SHA-256, and strict canonical JSON parameters (`allow_nan=False`, no `default=str`).
     - `HILKeyRing` requires >=32-byte high-entropy keys, rejects known/predictable keys, and supports zero-downtime key rotation (`rotate_key`) and key retirement (`retire_key`).
     - `GrantConsumptionStore` (`SQLiteAtomicGrantConsumptionStore` / `FirestoreTransactionalGrantConsumptionStore`) atomically records each consumed `grant_id` inside an exclusive transaction (`BEGIN IMMEDIATE` / Firestore `create()` precondition) so concurrent threads, multiple worker processes, or restarted processes can never consume the same grant twice. Storage failures raise `GrantStorageError` and fail closed (`DENIED_STORAGE_FAILURE`).

4. **Boundary TB-4: Application Runtime <-> Multi-Tenant Persistence (`FirebaseSyncManager`, `PersistenceBackend`)**
   - **Untrusted Inputs:** Artifact hashes, filenames, job IDs, finding IDs, blob paths, and tenant identifiers.
   - **Enforcement:**
     - `FirebaseSyncManager._resolve_tenant(user, tenant_id)` requires a cryptographically verified `AuthUserContext` and derives the effective tenant from `user.tenant_id` (raising `PersistencePermissionError` on cross-tenant mismatch).
     - `validate_tenant_id`, `validate_artifact_sha256`, `validate_document_id`, and `validate_storage_blob_path` reject `..` path traversal, slashes in IDs, null bytes, and URI schemes (`gs://`, `http://`, `file://`).
     - `ProductionFirestoreStorageAdapter` verifies `data["tenant_id"] == tenant_id` on every fetched document and raises `PersistencePermissionError` on permission denial or cross-tenant mismatch and `PersistenceUnavailableError` on backend/network failures rather than returning `None`.

5. **Boundary TB-5: Host Operating System <-> Binary Analysis & Dynamic Emulation Engines**
   - **Untrusted Inputs:** Potentially hostile binary artifacts (ELF, PE, Mach-O, minidumps, bytecode).
   - **Enforcement:**
     - `ProvenanceManager.ingest_artifact()` copies the target binary into an isolated workspace directory and marks the working copy read-only (`0444`).
     - Dynamic execution stages (`UnderConstrainedMicroVisor`, `DeterministicCPUEmulator`, `InvestigationWorkflowEngine._run_stage6_dynamic_execution`) perform bounded in-memory instruction emulation and generate confinement profiles (`detonation_profile.wsb`, `posix_isolated_runner.sh`, `frida_telemetry.js`) without executing the untrusted binary directly on the host OS.
     - Heuristic/concolic findings (`ConcolicSymbolicOrchestrator`, `ConcolicPathPruner`) are explicitly labeled with non-confirmed confidence (`Theoretical` / `Possible`) so unverified symbolic hypotheses are never misrepresented as confirmed crashes.

---

## 2. Adversarial Threat Scenarios & Mitigations

| Threat ID | Adversary Goal | Attack Vector | Mitigation & Verification |
|:---|:---|:---|:---|
| **TM-01** | Mint HIL approvals without operator authorization | Construct `ApprovalGrant` using the legacy hardcoded key `rf_hil_internal_signing_key_bicentennial_2026` or call `ApprovalGrant.create()`. | Legacy key removed and blocklisted in `normalize_and_validate_signing_key`; `ApprovalGrant.create()` raises `AuthorizationDeniedError`; `ApprovalIssuer` requires a sealed `AuthUserContext` and high-entropy `HILKeyRing`. |
| **TM-02** | Replay a captured `ApprovalGrant` across concurrent requests or after service restart | Send 12 simultaneous requests with the same `X-HIL-Approval-Grant` header, or replay a grant after worker restart. | `SQLiteAtomicGrantConsumptionStore` (`BEGIN IMMEDIATE` on `PRIMARY KEY (grant_id)`) and `FirestoreTransactionalGrantConsumptionStore` (`doc_ref.create()`) guarantee at-most-once atomic consumption across threads, processes, and restarts. |
| **TM-03** | Forge a privileged `LEAD_ARCHITECT` identity in Python or via JWT algorithm confusion | Call `AuthUserContext(uid="x", role=UserRole.LEAD_ARCHITECT, is_verified=True)` directly, or sign an `HS256` JWT using the server's public RSA PEM key. | `AuthUserContext.__post_init__` downgrades unsealed contexts to `is_verified=False`; `validate_key_algorithm_compatibility` blocks asymmetric keys from `HS*` algorithms; `resolve_role` rejects unknown role strings. |
| **TM-04** | Swap a benign binary with a malicious payload after Stage 0 ingestion or HIL approval (TOCTOU) | Replace or append bytes to `target.elf` on disk after `ApprovalIssuer.issue_grant()` signs the original SHA-256. | `CentralAuthorizationBoundary._verify_on_disk_sha256` and `PipelineStateMachine._verify_toctou_integrity` recompute the on-disk SHA-256 immediately before stage execution and deny with `DENIED_HIL_TARGET_MISMATCH`. |
| **TM-05** | Bypass pipeline authorization by calling private `_stage_N()` methods directly | Call `pipe._stage_7()` or `pipe._stage_11()` directly instead of `pipe.execute_stage()`. | Every `_stage_0`..`_stage_11` method invokes `_enforce_direct_stage_entry` / `CentralAuthorizationBoundary.evaluate_request` and `_verify_toctou_integrity` before performing any work. |
| **TM-06** | Read or overwrite another tenant's artifacts via path traversal or error masking | Pass `tenant_id="../tenant_a"` or `blob_path="../../secret"` to persistence adapters, or rely on backend errors returning `None`. | `validate_tenant_id`, `validate_artifact_sha256`, `validate_document_id`, and `validate_storage_blob_path` raise `ValueError`; `FirebaseSyncManager` derives tenant from the verified principal and raises `PersistencePermissionError` / `PersistenceUnavailableError`. |
