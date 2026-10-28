# Phase 4.2 Baseline Audit & Environment Verification

**Document:** `docs/PHASE4_2_BASELINE.md`  
**Date:** 2026-10-28  
**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Phase:** 4.2 — HIL Authorization Bypass Closure, Execution Boundary Hardening & Release Gate  

## 1. Repository & Execution Environment Baseline

- **Starting Git Commit SHA:** `ee72d0c811b33ce7563463f7e4e93be3a496c81c` (`feat(phase4.1): trust boundary closure, security remediation & independent verification`)
- **Current Branch:** `main`
- **Working-Tree Status Before Phase 4.2:** Clean (tracking `origin/main` at `ee72d0c811b33ce7563463f7e4e93be3a496c81c`)
- **Host / Sandbox Environment Details:**
  - **OS / Kernel:** Debian GNU/Linux 12 (bookworm) x86_64 (`Linux kali 6.12.0-kali1-amd64`)
  - **Python Version:** `Python 3.11.2` (`/usr/bin/python3`)
  - **Packaging Toolchain:** `pip 24.2`, `setuptools 80.9.0`, `wheel 0.45.1`, `build`
  - **Cryptography Libraries:** `cryptography 38.0.4` (system installed), `PyJWT 2.8.0`
  - **C Toolchain:** `gcc (Debian 12.2.0-14+deb12u1) 12.2.0`, `nm`, `objdump`, `readelf`
  - **Rust Toolchain:** `rustc` and `cargo` are not installed locally in this offline VM environment (`command not found`). Native pre-built libraries `rust_core/bin/libreverse_forge_core.so` and `rust_core/bin/reverse-forge-native` are present and verified via ABI validation tests; C fallback bridge is present at `rust_core/c_fallback_bridge.c`. Full `cargo fmt`, `cargo check`, `cargo clippy -- -D warnings`, and `cargo test` run in GitHub Actions CI under `ubuntu-latest`.
  - **Network / Cloud Infrastructure:** Outbound public Internet and live GCP Firestore/Firebase credentials (`FIREBASE_SERVICE_ACCOUNT_KEY`, `FIRESTORE_EMULATOR_HOST`) are absent in this local execution sandbox. All persistence is tested via `LocalSimulationPersistenceAdapter` and mocked Firestore SDK (`ProductionFirestoreStorageAdapter` with simulated Google Cloud auth).

## 2. Baseline Test Status Prior to Phase 4.2

Targeted Phase 4.1 regression suites:
- `tests/test_phase4_authorization_bypass.py`: 37 passed
- `tests/test_phase4_auth_hardening.py`: 23 passed
- `tests/test_firebase_sync.py`: 62 passed
- `tests/test_security_regressions.py`: 20 passed
- `tests/test_phase4_e2e_acceptance.py`: 2 passed
- Subtotal: 144 passed, 0 failures, 0 errors.

## 3. Scope and Gaps Identified at Start of Phase 4.2

Despite the substantial hardening delivered in Phase 4.1, a rigorous zero-trust audit revealed three critical residual security gaps:

1. **`InvestigationWorkflowEngine.submit_hil_decision()` Non-Production Bypass (P4.2-F01)**:
   Line 313 of `reverse_forge/investigation_workflow.py` retained a conditional check:
   ```python
   is_prod = os.environ.get("REVERSE_FORGE_ENV", "").strip().lower() == "production"
   enforce_boundary = bool(strict_auth or is_prod or principal is not None or approval_grant is not None)
   if decision == "APPROVE_SANDBOXED" and enforce_boundary:
   ```
   When `REVERSE_FORGE_ENV != "production"`, `strict_auth=False`, and no `principal` or `approval_grant` was passed, `enforce_boundary` evaluated to `False`. The engine recorded `decision="APPROVE_SANDBOXED"` directly in `hil_history` and resumed execution to Stage 6 dynamic execution without calling `CentralAuthorizationBoundary.evaluate_request()`, without verifying credentials, and without consuming a signed `ApprovalGrant`.

2. **`InvestigationWorkflowEngine._is_hil_approved()` History Poisoning (P4.2-F02)**:
   Line 621 of `reverse_forge/investigation_workflow.py` accepted any historical record where `rec.get("action") == action and rec.get("decision") == "APPROVE_SANDBOXED"` without verifying whether that record was authenticated cryptographically via `CentralAuthorizationBoundary`. If an unauthenticated approval record was injected into `hil_history`, `_run_stage6_dynamic_execution` was tricked into executing dynamic analysis.

3. **GUI Server Conditional Auth Bypass on `/api/upload` and `/api/annotate` (P4.2-F03)**:
   In `reverse_forge/gui_server.py`, lines 3915 and 3939 enforced authentication only conditionally:
   ```python
   if self.strict_auth or firebase_sync.auth.is_production or self.headers.get("Authorization"):
   ```
   In default dev/test mode without an `Authorization` header, unauthenticated callers could upload arbitrary binaries and create arbitrary annotations without authentication or RBAC authorization.
