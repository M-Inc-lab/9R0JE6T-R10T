# 9R0JE6T-R10T Security Architecture & Threat Model

**Document Version:** 4.0.0  
**Phase:** Phase 4 — Security Enforcement, CI Recovery & Real Persistence  
**Date:** 2026-10-28  

---

## 1. Principles of Security Architecture
The `R3V3R53//F0RG3` reverse engineering platform adheres to a strict **fail-closed**, **least-privilege**, and **evidence-driven** security foundation:
1. **Zero Unverified Trust**: Tokens, binary payloads, external libraries, and operator inputs are treated as untrusted until verified cryptographically or validated against explicit bounds.
2. **Fail-Closed Policy Enforcement**: Any missing credential, absent authorization callback, malformed header, or unexpected binary format results in immediate, explicit termination with a structured diagnostic state.
3. **No Autonomy Bypass**: Operator autonomy configuration dictates task automation within permitted bounds, but cannot override mandatory safety, boundary, or execution policy.
4. **Honest Persistence Separation**: Local in-memory simulations are strictly demarcated from cloud infrastructure, preventing false security assurances.
5. **Zero Side-Effects on Denial**: Denied operations are aborted immediately before touching disk, altering artifacts, or performing network operations.

---

## 2. Authentication & Identity Provider (IdP) Verification

### Token Verification Flow
Token authentication is implemented in `reverse_forge/firebase_sync.py` via `FirebaseAuthManager`:
- **Cryptographic Signature Verification**: Validated via `PyJWT` with standard asymmetric (`RS256`, `ES256`) or symmetric (`HS256`) key verification.
- **Header & Algorithm Enforcement**: The insecure `alg: none` header and unauthorized algorithms are categorically rejected.
- **Claim Checks**:
  - `exp` (Expiration Time): Enforced with 0-second leeway; expired tokens are rejected.
  - `nbf` (Not Before): Enforced to prevent premature token use.
  - `iss` (Issuer): Verified against the configured trusted IdP (e.g., `https://securetoken.google.com/<project-id>`).
  - `aud` (Audience): Enforced to match the designated project or application client ID.
  - `sub` (Subject): Required subject identifier.
- **Revocation & Identity Checks**: Role-based access control (`RBAC`) evaluates `role` and `tenant_id` from cryptographically verified claims. Privileged operations are never granted to unverified tokens.
- **Key Malformation Handling**: Corrupted or malformed verification keys fail closed gracefully, logging a warning without crashing.

### Production vs Development Isolation
- **Mock Authentication Guard**: Mock authentication tokens (prefixed with `mock-token-` or `dev-token-`) are permitted **only** when `allow_dev_mock=True` and `REVERSE_FORGE_ENV != "production"`.
- If `REVERSE_FORGE_ENV=production` or missing authorization headers are presented, requests fail closed immediately, returning an unverified context (`is_verified=False`).

---

## 3. Centralized Execution Authorization & TOCTOU Boundary

### CentralAuthorizationBoundary (`reverse_forge/authorization.py`)
All routes into sensitive operations (direct handler calls, pipeline stages, background tasks, tool adapters) are evaluated immediately before execution side-effects occur.

The boundary enforces:
1. **Principal Verification**: `principal.is_verified` must be `True`. Unverified principals are strictly denied for any sensitive operation.
2. **Tenant Ownership**: `principal.tenant_id == target_tenant_id`. Cross-tenant reads and writes are blocked.
3. **Role-Based Access Control**:
   - `DELETE_ARTIFACT`: Requires `LEAD_ARCHITECT`.
   - `MODIFY_ARTIFACT`, `REMEDIATION_PATCH`, `DYNAMIC_SANDBOX`, `NETWORK_ACCESS`: Requires `ANALYST` or `LEAD_ARCHITECT`.
   - `VIEWER`: Strictly read-only (disassembly, static metadata, reports).
4. **Scope Policy**: `ScopeLedger.is_authorized` must permit the canonical realpath and action.
5. **Cryptographic ApprovalGrants**:
   - Mandatory HIL operations (`DYNAMIC_SANDBOX`, `NETWORK_ACCESS`, `DELETE_ARTIFACT`, `MODIFY_ARTIFACT`) require a cryptographically HMAC-signed `ApprovalGrant`.
   - The grant binds: `(operation, target_sha256, parameters_hash, approver_uid, issued_at, expires_at)`.
   - Grants have strict TTLs (default 300s), are invalidated on parameter modification or target mismatch, and cannot be replayed once consumed.
6. **Autonomy Non-Override Invariant**: Mandatory HIL policy cannot be bypassed by `AutonomyLevel.AUTONOMOUS` or `AutonomyLevel.CONTINUOUS`.

---

## 4. Multi-Tenant Cloud Persistence

### Production Firestore & Cloud Storage (`ProductionFirestoreStorageAdapter`)
- Built on official `google-cloud-firestore` and `google-cloud-storage` SDKs.
- Enforces tenant isolation on all collections and storage buckets:
  - Artifact Metadata: `tenants/{tenant_id}/artifacts/{sha256}`
  - Findings: `tenants/{tenant_id}/artifacts/{sha256}/findings/{finding_id}`
  - Analysis Jobs: `tenants/{tenant_id}/jobs/{job_id}`
  - Blobs: `gs://{bucket}/tenants/{tenant_id}/{path}`
- Fails closed with `RuntimeError` if required credentials (`FIREBASE_SERVICE_ACCOUNT_KEY`) are missing.
- Never fabricates storage URIs or upload success indicators without actual bytes written.

---

## 5. Native Execution & Toolchain Cache Invalidation

### Dynamic Native Bridge Security (`reverse_forge/native_rust_bridge.py`)
1. **Toolchain & Build Fingerprinting**: Native shared objects are cached with SHA-256 fingerprints incorporating:
   - Source code: `Cargo.toml`, `c_fallback_bridge.c`, `standalone_cli.c`, `src/*.rs`
   - Toolchain versions: `rustc --version`, `gcc` / `clang` compiler version
   - Build flags: `CFLAGS=-O3 -shared -fPIC -lm;RUSTFLAGS=--release`
   - Host platform, machine architecture, and ABI version (`v2`)
2. **ABI Verification Vectors**:
   - Known IDA FLIRT CRC-16 vector: `b"123456789"` -> `0x906E`
   - Shannon Entropy of empty buffer: `0.0`
   - FNV1a-64 of `b"test"`: `0xf9e6e6ef197c2b25`
3. **Fail-Closed ABI Invalidation**: Corrupted libraries or missing required symbols (`rf_rust_entropy`, `rf_rust_flirt_crc16`, `rf_rust_fnv1a_64`, `rf_rust_visor_exec`, `rf_rust_pcode_decompile`) immediately fail closed and retain compiler diagnostics.
