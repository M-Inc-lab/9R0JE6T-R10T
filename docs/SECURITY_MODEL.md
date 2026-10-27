# 9R0JE6T-R10T Security Architecture & Threat Model

## 1. Principles of Security Architecture
The `R3V3R53//F0RG3` reverse engineering platform adheres to a strict **fail-closed**, **least-privilege**, and **evidence-driven** security foundation:
1. **Zero Unverified Trust**: Tokens, binary payloads, external libraries, and operator inputs are treated as untrusted until verified cryptographically or validated against explicit bounds.
2. **Fail-Closed Policy Enforcement**: Any missing credential, absent authorization callback, malformed header, or unexpected binary format results in immediate, explicit termination with a structured diagnostic state.
3. **No Autonomy Bypass**: Operator autonomy configuration dictates task automation within permitted bounds, but cannot override mandatory safety, boundary, or execution policy.
4. **Honest Persistence Separation**: Local in-memory simulations are strictly demarcated from cloud infrastructure, preventing false security assurances.

---

## 2. Authentication & Identity Provider (IdP) Verification

### Token Verification Flow
Token authentication is implemented in `reverse_forge/firebase_sync.py` via `FirebaseAuthManager`:
- **Cryptographic Signature Verification**: Validated via `PyJWT` with standard asymmetric (`RS256`, `ES256`) or symmetric (`HS256`) key verification.
- **Header & Algorithm Enforcement**: The insecure `alg: none` header is categorically rejected.
- **Claim Checks**:
  - `exp` (Expiration Time): Enforced with 0-second leeway by default; expired tokens are rejected.
  - `nbf` (Not Before): Enforced to prevent premature token use.
  - `iss` (Issuer): Verified against the configured trusted IdP (e.g., `https://securetoken.google.com/<project-id>`).
  - `aud` (Audience): Enforced to match the designated tenant or application client ID.
- **Revocation & Identity Checks**: Role-based access control (`RBAC`) evaluates `role` and `tenant_id` from cryptographically verified claims. Privileged operations are never granted to unverified tokens.

### Production vs Development Isolation
- **Mock Authentication Guard**: Mock authentication tokens (prefixed with `mock-token-` or `dev-token-`) are permitted **only** when `REVERSE_FORGE_ENV != "production"`.
- If `REVERSE_FORGE_ENV=production` or missing authorization headers are presented, requests fail closed immediately, returning an unverified context (`is_verified=False`).

---

## 3. Scope Enforcement, Path Traversal & Least Privilege

### ScopeLedger & Canonical Realpaths
Authorization over local filesystem targets is governed by `ScopeLedger` (`reverse_forge/provenance.py`):
- **Canonical Realpath Resolution**: Target paths are resolved via `os.path.realpath(os.path.abspath(target_path))` to defeat symlink escapes, relative path traversals (`../../`), and null-byte injection.
- **Default Deny**: An empty pattern list or unauthorized file path immediately denies execution before any file descriptor is opened or bytes are read from disk.
- **Explicit Action Permissions**: Permissions are classified under the `ActionPermission` enum:
  - `READ_HASH`: Artifact hashing and checksum extraction.
  - `STATIC_ANALYSIS`: Disassembly, format parsing, and AST construction.
  - `DYNAMIC_SANDBOX`: Under-constrained micro-visor or guest VM execution.
  - `NETWORK_ACCESS`: Outbound communication to package repositories or cloud endpoints.
  - `MODIFY_ARTIFACT`: Mutation of working copies, patch application, or metadata writing.
  - `EXPORT_REPORT`: Writing findings to designated output paths.
  - `EXTERNAL_SERVICE`: Dispatches to external analyzers (Ghidra, Rizin, IDA).
  - `DESTRUCTIVE_OP`: Irreversible remediation or storage purges.

---

## 4. Human-in-the-Loop (HIL) Safety Policy

### Fail-Closed Gate Mechanism
Dynamic execution, sandbox networking, and artifact modification present acute security risks when processing hostile or weaponized binaries.
In `reverse_forge/pipeline.py` (`_check_hil_gate`):
- **Mandatory Callback**: For sensitive actions (`DYNAMIC_SANDBOX`, `NETWORK_ACCESS`, `MODIFY_ARTIFACT`), if no operator callback is registered (`hil_callback is None`), the gate **strictly denies** execution fail-closed.
- **Autonomy Level Boundary**: While autonomy levels `0`–`4` automate progression across static analysis stages, high autonomy (`AutonomyLevel.FULL_AUTONOMY`) is forbidden from bypassing HIL gates on sensitive or destructive actions.
- **Denial Auditing**: Denials record the target, requested action, and stage in provenance records with `StageStatus.FAILED` or `StageStatus.SKIPPED`.

---

## 5. Multi-Tenant Cloud & Persistence Isolation

### Tenant Separation
Multi-tenant operations in `reverse_forge/firebase_sync.py` enforce strict isolation at the storage adapter level:
- In `LocalSimulationPersistenceAdapter`, artifacts, jobs, and findings are stored in isolated namespaces keyed by `tenant_id`:
  ```python
  self._tenant_artifacts[tenant_id][artifact_id] = data
  ```
- Any attempt to read or modify an artifact belonging to `tenant_A` using credentials from `tenant_B` is rejected with an explicit `PermissionError`.
- Simulated URIs use the scheme `local-sim://<tenant>/<artifact>`, preventing confusion with real cloud storage (`gs://`).

### Cloud Adapter Realism
- `ProductionFirestoreStorageAdapter` is cleanly separated from the simulation adapter.
- In environments where Google Cloud credentials or Firebase Emulator configurations are missing, production persistence calls are rejected fail-closed with an explicit configuration blocker rather than silently falling back to uncommitted memory.

---

## 6. Native Execution & ABI Verification

### Dynamic Native Bridge Security
Native Rust and C fallback bridges (`reverse_forge/native_rust_bridge.py`) are secured against execution hijacking and ABI mismatch:
1. **Source & Build Fingerprinting**: Native shared objects are compiled into versioned caches named by the SHA-256 digest of compiler version, host platform, and source files (`src/*.rs`, `c_fallback_bridge.c`).
2. **Concurrency Safety**: Native compilation is guarded by process-level locks (`_compile_lock`), preventing race conditions or corrupted partial writes during multi-threaded execution.
3. **ABI Verification Vector**: On library load, the bridge executes a known test vector (`b"123456789"` through `rf_rust_flirt_crc16`) and asserts the output matches `0x906E`. If the ABI returns an unexpected value, the library is immediately invalidated and rejected.
4. **Explicit Backend Reporting**: Analysis artifacts explicitly record `backend_used` (`RUST_NATIVE`, `C_FALLBACK`, or `PURE_PYTHON`). C execution is never reported as Rust execution.
