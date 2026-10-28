# Phase 4.2 Security Findings & Remediation Ledger

**Document:** `docs/PHASE4_2_SECURITY_FINDINGS.md`  
**Date:** 2026-10-28  
**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Phase:** 4.2 — HIL Authorization Bypass Closure, Execution Boundary Hardening & Release Gate  

---

### Finding P4.2-F01: Conditional HIL Authorization Bypass in `InvestigationWorkflowEngine.submit_hil_decision()`

- **Severity:** **CRITICAL** (CVSS: 9.8 / CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Component:** `reverse_forge/investigation_workflow.py` (`submit_hil_decision`)
- **Affected Code:** Line 313 of `reverse_forge/investigation_workflow.py`:
  ```python
  is_prod = os.environ.get("REVERSE_FORGE_ENV", "").strip().lower() == "production"
  enforce_boundary = bool(strict_auth or is_prod or principal is not None or approval_grant is not None)
  if decision == "APPROVE_SANDBOXED" and enforce_boundary:
  ```
- **Exploit Preconditions:**
  - `REVERSE_FORGE_ENV` is unset or not `"production"` (standard development, staging, or test environments).
  - Caller does not pass `strict_auth=True`.
  - Caller invokes `submit_hil_decision(inv_id, action="dynamic_execution", decision="APPROVE_SANDBOXED", operator="attacker")` without `principal` and without `approval_grant`.
- **Impact:**
  - Complete bypass of `CentralAuthorizationBoundary`.
  - Operator authentication, RBAC role verification, tenant isolation, and single-use cryptographic grant verification were completely skipped.
  - An unauthorized attacker or unauthenticated process could unpause a blocked investigation and trigger Stage 6 dynamic sandboxed execution / in-memory micro-visor emulation on any binary without human authorization.
- **Remediation:**
  - Eliminated the `enforce_boundary` conditional logic entirely.
  - Every `APPROVE_SANDBOXED` decision now **unconditionally** routes through `CentralAuthorizationBoundary.evaluate_request()`.
  - Missing, unsealed, or unverified principal identity, or missing/invalid cryptographic approval grant fails closed with `AuthorizationDeniedError`.
  - The `strict_auth` parameter is retained for API backward compatibility as an intentional no-op; strict enforcement is permanent.
  - Legitimate `REJECT_STATIC_ONLY` decisions do not execute dynamic code and do not require HIL credentials.
- **Regression Test:**
  - `tests/test_phase4_2_hil_bypass_closure.py`:
    - `test_p42_no_principal_no_grant_approve_sandboxed_denied`
    - `test_p42_missing_env_var_does_not_bypass`
    - `test_p42_dev_env_does_not_bypass`
    - `test_p42_strict_auth_false_is_now_noop`
    - `test_p42_forged_principal_is_denied`
    - `test_p42_expired_grant_denied`
    - `test_p42_tampered_signature_denied`
    - `test_p42_wrong_sha256_grant_denied`
    - `test_p42_wrong_operation_grant_denied`
    - `test_p42_authorized_principal_and_valid_grant_succeeds`
    - `test_p42_reject_static_only_needs_no_authorization`
- **Residual Risk:** None. The conditional check has been removed from the source code; authorization evaluation is unconditional.

---

### Finding P4.2-F02: State History Poisoning in `InvestigationWorkflowEngine._is_hil_approved()`

- **Severity:** **HIGH** (CVSS: 8.1 / CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
- **Component:** `reverse_forge/investigation_workflow.py` (`_is_hil_approved`)
- **Affected Code:** Lines 619–622 of `reverse_forge/investigation_workflow.py`:
  ```python
  def _is_hil_approved(self, state: InvestigationState, action: str) -> bool:
      for rec in state.hil_history:
          if rec.get("action") == action and rec.get("decision") == "APPROVE_SANDBOXED":
              return True
      return False
  ```
- **Exploit Preconditions:**
  - An attacker or deserialization routine inserts an entry `{"action": "dynamic_execution", "decision": "APPROVE_SANDBOXED"}` into `state.hil_history` without passing through the cryptographic authorization boundary.
- **Impact:**
  - When `execute_next_stage()` or direct invocation of `_run_stage6_dynamic_execution()` was called, `_is_hil_approved()` returned `True`, believing human approval had occurred.
  - Allowed execution of dynamic micro-visor emulation on poisoned investigations.
- **Remediation:**
  - Updated `submit_hil_decision()` to record `"cryptographic_auth": True` only after `CentralAuthorizationBoundary.evaluate_request()` has successfully verified and consumed a valid signed `ApprovalGrant`.
  - Updated `_is_hil_approved()` to require both `rec.get("decision") == "APPROVE_SANDBOXED"` **and** `rec.get("cryptographic_auth") is True`.
  - Unauthenticated entries, legacy bypass entries, or injected records without cryptographic authentication are rejected.
- **Regression Test:**
  - `tests/test_phase4_2_hil_bypass_closure.py`:
    - `test_legacy_record_without_cryptographic_auth_rejected`
    - `test_poisoned_history_without_cryptographic_auth_rejected`
    - `test_cryptographic_auth_true_accepted`
    - `test_execute_next_stage_fails_with_poisoned_history`
- **Residual Risk:** None. History inspection strictly requires boolean `cryptographic_auth: True`.

---

### Finding P4.2-F03: Conditional Authentication Bypass on GUI Write Endpoints (`/api/upload` & `/api/annotate`)

- **Severity:** **HIGH** (CVSS: 7.5 / CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
- **Component:** `reverse_forge/gui_server.py` (`GUIWorkbenchHandler.do_POST`)
- **Affected Code:** Lines 3915 & 3939 of `reverse_forge/gui_server.py`:
  ```python
  if self.strict_auth or firebase_sync.auth.is_production or self.headers.get("Authorization"):
  ```
- **Exploit Preconditions:**
  - Non-production mode (`firebase_sync.auth.is_production=False`).
  - `strict_auth=False`.
  - Request sent without an `Authorization` header.
- **Impact:**
  - An unauthenticated caller could upload arbitrary binary artifacts to the server temp directory.
  - An unauthenticated caller could inject arbitrary annotations into active investigations without any identity or role verification.
- **Remediation:**
  - Removed the conditional check on `/api/upload` and `/api/annotate`.
  - `user = self._get_auth_user()` is now called unconditionally.
  - Requests missing valid cryptographic authentication fail closed with HTTP 401 Unauthorized.
  - Requests lacking write permissions (`user.can_modify()`) fail closed with HTTP 403 Forbidden.
- **Regression Test:**
  - `tests/test_phase4_2_hil_bypass_closure.py`:
    - `test_upload_requires_auth_without_strict_auth`
    - `test_upload_requires_auth_with_strict_auth_true`
    - `test_annotate_requires_auth_without_strict_auth`
    - `test_annotate_requires_auth_with_strict_auth_true`
    - `test_upload_and_annotate_succeed_with_valid_auth`
- **Residual Risk:** None. All POST write endpoints require verified authentication unconditionally.

---

### Finding P4.2-F04: Async Pipeline Polling Race Under Host Load in Test Suite

- **Severity:** **LOW** (Test Stability / False Failure)
- **Component:** `tests/test_v32_cloud_concurrency_security.py` (`test_api_pipeline_async_and_jobs_polling`)
- **Affected Code:** Polling loop in `test_api_pipeline_async_and_jobs_polling` ran for 40 iterations of 0.05s (2.0s maximum total).
- **Exploit Preconditions:**
  - High CPU utilization or comprehensive 12-stage pipeline execution taking 10–18s to execute across symbolic, decompiler, and Ghidra analysis phases.
- **Impact:**
  - Test aborted polling while the job was still in `"RUNNING"` state, failing the assertion `self.assertIn(job["status"], ("COMPLETED", "FAILED"))`.
- **Remediation:**
  - Adjusted polling timeout to 250 iterations of 0.1s (25s total), ensuring background pipeline completion without false positive test failures.
- **Regression Test:**
  - `tests/test_v32_cloud_concurrency_security.py` passes 12/12.
- **Residual Risk:** None.
