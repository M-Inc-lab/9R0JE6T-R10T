# Phase 4.1 Baseline Audit & Environment Verification

**Document:** `docs/PHASE4_1_BASELINE.md`  
**Date:** 2026-10-28  
**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Phase:** 4.1 — Trust Boundary Closure, Security Remediation & Independent Verification  

## 1. Repository & Environment Baseline

- **Upstream Archive Commit SHA:** `d10d1dfe7b11a7348af07136decccb959d483d7f` (extracted from GitHub archive `9R0JE6T-R10T-d10d1dfe7b11a7348af07136decccb959d483d7f`, zip archive comment `d10d1dfe7b11a7348af07136decccb959d483d7f`).
- **Local Baseline Git Commit SHA:** `d3e4b678f7b7738667960f9c8a14e54edf45ba31` (initialized on branch `main` from the exact unmodified archive tree because GitHub zip archives omit `.git/`).
- **Working-Tree Status Before Remediation:** Clean (`git status -s` empty on baseline snapshot).
- **Host / Sandbox Environment:**
  - **OS / Kernel:** Debian GNU/Linux 12 (bookworm) x86_64
  - **Python Version:** `Python 3.11.2` (`/usr/bin/python3`)
  - **Packaging Toolchain:** `pip 24.2`, `setuptools 80.9.0`, `wheel 0.45.1`
  - **Cryptography Library:** `cryptography 38.0.4` (system package installed)
  - **C Toolchain:** `gcc (Debian 12.2.0-14+deb12u1) 12.2.0`, `nm`, `objdump`, `readelf`
  - **Rust Toolchain:** `rustc` and `cargo` are not installed in this isolated VM (`command not found`). Pre-built native artifacts `rust_core/bin/libreverse_forge_core.so` and `rust_core/bin/reverse-forge-native` are present in the repository alongside `rust_core/c_fallback_bridge.c`.
  - **Available Test Runner:** `python3 -m unittest discover -s tests -p "test_*.py" -v` (`pytest` CLI is not installed in the sandbox VM).
  - **Network / Cloud Access:** Outbound internet access and live GCP/Firebase credentials (`FIREBASE_SERVICE_ACCOUNT_KEY`, `FIRESTORE_EMULATOR_HOST`) are unavailable in the sandbox VM.

## 2. Baseline Test Execution & Observed Failures

Executing the unmodified test suite at baseline (`python3 -m unittest discover -s tests -p "test_*.py" -v`):

- **Total Tests Executed:** 444
- **Passed:** 425
- **Failures:** 2
- **Errors:** 14
- **Skipped:** 3

### Breakdown of Baseline Failures & Errors

1. **`test_full_pipeline_on_elf_binary` (`tests/test_phase3_pipeline.py`) — FAILED**:
   - Stage 10 (`Reproducibility & Report Generation`, mapped to `OperationType.EXPORT_REPORT` -> `ActionPermission.EXPORT_REPORT`) failed with:
     `Security Policy Denied: Scope ledger policy denied action 'export_report' for target '/bin/ls'`
   - **Root Cause:** `ScopeLedger.is_authorized()` blocks `EXPORT_REPORT`, `MODIFY_ARTIFACT`, and `DESTRUCTIVE_OP` when the target path resolves inside system directories (`/bin`, `/usr/bin`). However, `PipelineStateMachine` passed `self.artifact_path` (`/bin/ls`) instead of the isolated workspace copy / report output path in `self.provenance_mgr.workspace_root` when evaluating in-memory report generation (Stage 10) and remediation patch synthesis (Stage 11), and did not include `workspace_root` in its default `ScopeLedger.allowed_paths`.
2. **`test_patches_1_to_4_z3_binding_colab_tls_and_requirements_sync` (`tests/test_phase66_70_eternal_upgrade.py`) — FAILED**:
   - Failed on `self.assertTrue(os.path.isdir(os.path.join(repo_root, ".git")))` prior to `git init` because the uploaded GitHub archive omitted `.git/`.
3. **14 Errors in `tests/test_firebase_sync.py` and `tests/test_phase4_e2e_acceptance.py` — ERROR**:
   - Caused by `ModuleNotFoundError: No module named 'jwt'` / `AttributeError: 'NoneType' object has no attribute 'encode'` because external `PyJWT` is not pre-installed in the sandbox VM while `cryptography 38.0.4` is installed.

## 3. Code-vs-Documentation Discrepancies Identified in Phase 4 Audit

Comparing the actual source code (`reverse_forge/authorization.py`, `reverse_forge/firebase_sync.py`, `reverse_forge/pipeline.py`, `reverse_forge/provenance.py`, `reverse_forge/gui_server.py`, `reverse_forge/investigation_workflow.py`, `.github/workflows/ci.yml`) against `docs/PHASE4_*.md`, `docs/SECURITY_MODEL.md`, and `docs/CAPABILITY_MATRIX.md` revealed the following critical gaps:

| ID | Priority | Component | Observed Defect in Baseline Code |
|---|---|---|---|
| **P4.1-FIND-001** | P0 | `reverse_forge/authorization.py` | `ApprovalGrant._get_internal_signing_key()` falls back to a hard-coded secret (`b"rf_hil_internal_signing_key_bicentennial_2026"`). Missing or weak keys do not fail closed. |
| **P4.1-FIND-002** | P0 | `reverse_forge/authorization.py` | Approval issuance is not separated from verification: any caller can call `ApprovalGrant.create()` without authenticating or authorizing the approver; `CentralAuthorizationBoundary.enforce()` mints fallback grants on the fly; `evaluate_request()` allows self-approval via `hil_callback` using `principal.uid`; `ApprovalGrant` does not bind `tenant_id` or canonical `target_path`; `hash_parameters()` uses `default=str` and `str(sorted(params.items()))`, allowing ambiguous serialization collisions. |
| **P4.1-FIND-003** | P0 | `reverse_forge/authorization.py` | Single-use approval tracking uses a process-local `self._consumed_grants: Set[str]` that resets on process restart, does not synchronize across worker processes, does not bind tenant context, and has a check-then-act race window between `is_valid_for()` and `_consumed_grants.add()`. |
| **P4.1-FIND-004** | P0 | `reverse_forge/firebase_sync.py` | `AuthUserContext` is a plain dataclass where callers can set `is_verified=True` directly without cryptographic token verification. `FirebaseAuthManager` enables `["RS256", "ES256", "HS256"]` simultaneously without verifying key-algorithm compatibility, silently maps unknown role strings (e.g., `"SUPER_ADMIN"`) to `UserRole.ANALYST` (a privileged role), does not enforce server-side tenant membership bindings when `trusted_tenants` is unset, and `GUIWorkbenchHandler._get_auth_user()` fabricates a verified `LEAD_ARCHITECT` identity when `Authorization` header is missing in non-production mode. |
| **P4.1-FIND-005** | P0 | `reverse_forge/pipeline.py`, `gui_server.py`, `investigation_workflow.py`, `cli.py` | Multiple side-effecting entry points bypass `CentralAuthorizationBoundary`: direct stage handler calls (`_stage_0`..`_stage_6`, `_stage_8`..`_stage_10`), GUI endpoints (`/api/patch`, `/api/force-exec`, `/api/upload`, `/api/annotate`, `/api/pipeline`, `/api/investigate/*`, `/api/native-rust`, `/api/debug`), `InvestigationWorkflowEngine.submit_hil_decision()`, and direct sandbox/patcher/network methods. Target SHA-256 is not re-verified against disk immediately before execution (TOCTOU risk). |
| **P4.1-FIND-006** | P0 | `.github/workflows/ci.yml` | `Cargo clippy (deny warnings)` specifies `continue-on-error: true`. The `import rust_core` check runs inside the repository checkout (or with `PYTHONPATH: ${{ github.workspace }}`), where Python's PEP 420 `NamespaceLoader` imports `rust_core/` as a namespace package and causes false failures or fails to test actual wheel isolation outside the checkout. Third-party GitHub Actions are not pinned to immutable commit SHAs. |
| **P4.1-FIND-007** | P1 | `reverse_forge/firebase_sync.py` | `FirebaseSyncManager._resolve_tenant()` accepts caller-supplied `tenant_id` when `user=None`. `ProductionFirestoreStorageAdapter` does not validate `sha256`, `tenant_id`, `job_id`, `finding_id`, or `path` against path traversal/separators/URI schemes, and `get_blob()` swallows all backend exceptions (`except Exception: return None`), masking outages and permission denials as missing blobs. |
| **P4.1-FIND-008** | P1 | `reverse_forge/pipeline.py`, `tool_installer.py`, `docs/` | `PipelineStateMachine._stage_8()` synthesizes a dummy constraint `[PathConstraint(var="input_len", op="GT", value=0)]` for every sink xref and labels the result `confidence="Confirmed"` (`cvss_score=9.1`, `"SMT Proven Exploit Trigger Payload"`). `ToolchainInstaller.detect_all()` does not report Rizin/Cutter (`rizin`, `rz-bin`, `cutter`) alongside Radare2, Ghidra, and IDA. |
