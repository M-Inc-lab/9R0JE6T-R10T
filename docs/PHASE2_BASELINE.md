# Phase 2 — Forensic Security Hardening & Validation Baseline

## 1. Environment & Repository Baseline

- **Repository**: `https://github.com/M-Inc-lab/9R0JE6T-R10T.git`
- **Baseline Commit**: `5a6574e484471b0f5703c4f0fa733a93d4eebede`
- **Working Tree**: Clean (`main` branch synchronized with `origin/main`)
- **Execution Date**: 2026-10-27
- **Operating System**: Linux 6.12.38+kali-amd64 (`x86_64`)
- **Toolchain & Runtimes**:
  - Python: `3.14.6` (`GCC 15.2.0`)
  - Rust: `rustc 1.95.0 (59807616e 2026-04-14)`
  - Cargo: `cargo 1.95.0 (f2d3ce0bd 2026-03-21)`
  - GCC: `15.3.0 (Debian 15.3.0-2)`
  - Capstone: `5.0.7`
  - PyJWT: `2.13.0`
  - Cryptography: `47.0.0`
  - Rizin: `0.9.1` (`/usr/bin/rizin`)
  - Ghidra: `/usr/local/bin/ghidra`

---

## 2. Test Execution Outcomes at Baseline

### 2.1 Python Test Suite
- **Command**: `PYTHONPATH=. pytest -q`
- **Result**: **315 passed in 41.04s** (0 failed, 0 errors).
- **Coverage**: Includes security regression tests (`test_security_regressions.py`), Firebase sync tests (`test_firebase_sync.py`), differential analysis validation (`test_differential_analysis_validation.py`), pipeline tests (`test_phase3_pipeline.py`), and 26-format parser tests.

### 2.2 Native Rust Engine
- **Command**: `cargo test --manifest-path rust_core/Cargo.toml`
- **Result**: **3 passed in 0.06s** (`workflow_intent_engine`).
- **Build Status**: Compiles cleanly with 4 minor unused import warnings in P-Code IR.

### 2.3 Independent C Fallback Bridge
- **Command**: `gcc -O3 -shared -fPIC -Wall -Wextra -o /tmp/libreverse_forge_c_baseline.so rust_core/c_fallback_bridge.c -lm`
- **Result**: Exit code `0`; exported symbols verified (`rf_rust_entropy`, `rf_rust_flirt_crc16`, `rf_rust_visor_exec`).

---

## 3. Subsystem Architecture & Call Graph Analysis

### 3.1 Authentication & Identity Flow
- **Entry Points**:
  - `reverse_forge/firebase_sync.py:FirebaseAuthManager.verify_bearer_token(auth_header)`
  - `reverse_forge/gui_server.py:GUIWorkbenchHandler._get_auth_user()`
- **Consumers**:
  - `FirebaseSyncManager.sync_findings()`
  - `FirebaseSyncManager.sync_analysis_job()`
  - `FirebaseSyncManager.archive_binary()`
  - `gui_server.py` `/api/cloud/sync`, `/api/cloud/status`
- **Defects Identified**:
  1. *Default Issuer Omission*: `verify_bearer_token` omitted issuer validation when `expected_issuer == f"https://securetoken.google.com/{self.project_id}"`.
  2. *Unverified Dev Fallback Privilege*: In dev mode without a verification key, decoded claims were assigned directly to `AuthUserContext` without cryptographic signature verification, yet `can_modify()` did not check `is_verified`.
  3. *Missing Revocation Mechanism*: No token revocation / denylist check was implemented for compromised session invalidation.

### 3.2 Authorization, Scope & HIL Execution Boundary
- **Entry Points**:
  - `reverse_forge/provenance.py:ScopeLedger.is_authorized(target, action)`
  - `reverse_forge/pipeline.py:PipelineStateMachine._check_hil_gate(stage_idx, action)`
  - `reverse_forge/investigation_workflow.py:InvestigationWorkflowEngine._check_hil_gate()`
- **Direct Invocation Bypass Risks**:
  - `reverse_forge/gui_server.py`:
    - `/api/pipeline`: Passed `authorized_scope="*"` wildcard, bypassing target scope isolation.
    - `/api/force-exec`: Directly invoked `UnderConstrainedMicroVisor.force_execute_function()` without `DYNAMIC_SANDBOX` permission or HIL gate checks.
    - `/api/patch`: Directly invoked `BinaryPatcherEngine.save_patched_binary()` without `MODIFY_ARTIFACT` permission checks.
  - Basename collision risk in `ScopeLedger.is_authorized()`: `allowed_patterns` evaluated against `os.path.basename` without path containment.

### 3.3 Cloud Persistence & Multi-Tenant Separation
- **Entry Points**:
  - `reverse_forge/firebase_sync.py:FirebaseSyncManager`
  - `LocalSimulationPersistenceAdapter`
  - `ProductionFirestoreStorageAdapter`
- **Boundary Status**:
  - Simulation adapter strictly isolates records by `tenant_id` (`_tenant_artifacts[tenant_id]`) and returns `local-sim://` URIs.
  - Production adapter raises explicit blockers when Google Cloud credentials are unavailable.

### 3.4 Native Backend Selection & ABI Integrity
- **Entry Points**:
  - `reverse_forge/native_rust_bridge.py:NativeRustAccelerator`
- **Integrity Status**:
  - `_validate_abi()` verifies standard FLIRT CRC16 vector `"123456789"` -> `0x906E` before library load.
  - Cryptographic SHA-256 fingerprinting ensures versioned `.reverse_forge_workspace/native_cache/` isolation.

---

## 4. Phase 2 Hardening Action Plan

1. **Phase B (Authentication & Identity)**:
   - Enforce mandatory cryptographic verification for all non-dev tokens.
   - Enforce issuer and audience unconditionally.
   - Implement revocation denylist and server-side role validation.
   - Guard `AuthUserContext.can_modify()` and `is_lead()` with `is_verified`.
   - Implement exhaustive 14-case regression test suite.
2. **Phase C (Scope & HIL Enforcement)**:
   - Remove wildcard `authorized_scope="*"` from `gui_server.py`.
   - Protect `/api/force-exec`, `/api/patch`, `/api/pipeline` with ScopeLedger and HIL checks.
   - Harden `ScopeLedger` against basename-only escapes.
   - Add direct invocation policy enforcement tests.
3. **Phase D (Cloud Persistence & Tenant Isolation)**:
   - Verify tenant boundary checks across all CRUD operations.
4. **Phase E (Native Selection & Cache Hardening)**:
   - Add tests for corrupted native cache, compiler failure logging, forced backends.
5. **Phase F (Differential Analysis Corpus)**:
   - Expand benign test fixtures with known CFGs, indirect calls, and adversarial structures.
6. **Phase G (End-to-End Workflow)**:
   - Validate verified vertical slice on benign fixtures.
7. **Phase H (CI & Deliverables)**:
   - Update CI workflow and produce all required Phase 2 documentation.
