# Phase 4.2 Dynamic Execution Entry Point Audit

**Document:** `docs/PHASE4_2_EXECUTION_ENTRYPOINT_AUDIT.md`  
**Date:** 2026-10-28  
**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Phase:** 4.2 — HIL Authorization Bypass Closure, Execution Boundary Hardening & Release Gate  

---

## 1. Inventory of Execution Entry Points

| ID | File | Function / Endpoint | Operation Type | Pre-Phase 4.2 Status | Post-Phase 4.2 Remediation Status | Fail-Closed Mechanism |
|---|---|---|---|---|---|---|
| **EP-01** | `reverse_forge/investigation_workflow.py` | `submit_hil_decision` | `DYNAMIC_SANDBOX` | **VULNERABLE** (Bypassed if `REVERSE_FORGE_ENV != "production"` and `strict_auth=False`) | **HARDENED** (Unconditional `CentralAuthorizationBoundary.evaluate_request`) | Raises `AuthorizationDeniedError` on missing/unverified credentials |
| **EP-02** | `reverse_forge/investigation_workflow.py` | `_run_stage6_dynamic_execution` | `DYNAMIC_SANDBOX` | **VULNERABLE** (State history poisoning via `_is_hil_approved`) | **HARDENED** (Requires `cryptographic_auth: True` + TOCTOU SHA-256 recheck) | Raises `AuthorizationDeniedError` before reading/executing binary |
| **EP-03** | `reverse_forge/investigation_workflow.py` | `execute_next_stage` | `DYNAMIC_SANDBOX` | Calls EP-02 | **HARDENED** (Gated by EP-01 and EP-02) | Halts investigation, sets status to `BLOCKED_HIL` |
| **EP-04** | `reverse_forge/investigation_workflow.py` | `run_to_completion_or_hil` | `DYNAMIC_SANDBOX` | Calls EP-03 in loop | **HARDENED** (Automatically pauses at Stage 5, returns `BLOCKED_HIL`) | Never advances past Stage 5 without HIL approval |
| **EP-05** | `reverse_forge/gui_server.py` | `/api/investigate/approve` | `DYNAMIC_SANDBOX` | Hardened in P4.1, called EP-01 | **HARDENED** (Enforces verified auth + `can_modify` + forwards grant to EP-01) | HTTP 401 / 403 / 400 |
| **EP-06** | `reverse_forge/gui_server.py` | `/api/force-exec` | `DYNAMIC_SANDBOX` | Hardened in P4.1 | **HARDENED** (Enforces verified auth + `can_modify` + ScopeLedger + Boundary grant) | HTTP 401 / 403 |
| **EP-07** | `reverse_forge/gui_server.py` | `/api/upload` | `MODIFY_ARTIFACT` | **VULNERABLE** (Bypassed in dev mode when Authorization header missing) | **HARDENED** (Unconditional `_get_auth_user()` + `can_modify()`) | HTTP 401 / 403 |
| **EP-08** | `reverse_forge/gui_server.py` | `/api/annotate` | `MODIFY_ARTIFACT` | **VULNERABLE** (Bypassed in dev mode when Authorization header missing) | **HARDENED** (Unconditional `_get_auth_user()` + `can_modify()`) | HTTP 401 / 403 |
| **EP-09** | `reverse_forge/pipeline.py` | `_stage_7` (`_run_dynamic_analysis`) | `DYNAMIC_SANDBOX` | Hardened in P4.1 | **HARDENED** (Enforces `_check_hil_gate` + TOCTOU check; generates isolation scripts only; zero host execution) | Marked `SKIPPED`, raises in strict mode |
| **EP-10** | `reverse_forge/pipeline.py` | `_enforce_direct_stage_entry` | All Operations | Hardened in P4.1 | **HARDENED** (Every private `_stage_N()` method enforces TOCTOU & boundary evaluation) | Stage marked FAILED, raises in strict mode |
| **EP-11** | `reverse_forge/cli.py` | `main()` | `STATIC_ANALYSIS` / `MODIFY_ARTIFACT` | Hardened in P4.1 | **HARDENED** (CLI operations bounded to static analysis and bounded remediation templates) | Exits non-zero on scope/policy denial |

---

## 2. Detailed Audit of Remediation Mechanics

### EP-01 & EP-02: `InvestigationWorkflowEngine`

1. **Pre-execution Authorization:**
   Before any dynamic execution is performed, `submit_hil_decision()` enforces:
   ```python
   if decision == "APPROVE_SANDBOXED":
       auth_boundary = boundary or self.authorization_boundary
       target_path = state.spec.target_artifact_path
       target_sha = state.target_sha256 or ProvenanceManager.compute_hashes(target_path)["sha256"]
       permitted, dec, reason, consumed_grant = auth_boundary.evaluate_request(
           principal=principal,
           operation=OperationType.DYNAMIC_SANDBOX,
           target_path=target_path,
           target_sha256=target_sha,
           target_tenant_id=state.tenant_id,
           parameters={"investigation_id": inv_id, "action": action},
           approval_grant=approval_grant,
       )
       if not permitted:
           raise AuthorizationDeniedError(dec, reason, {})
   ```
2. **Pre-execution TOCTOU Revalidation:**
   Immediately before `_run_stage6_dynamic_execution()` reads data or executes the micro-visor:
   ```python
   target = state.spec.target_artifact_path
   if state.target_sha256 and os.path.isfile(target):
       current_sha = ProvenanceManager.compute_hashes(target)["sha256"]
       if current_sha != state.target_sha256:
           raise AuthorizationDeniedError(AuthorizationDecision.DENIED_HIL_TARGET_MISMATCH, "TOCTOU target hash mismatch before Stage 6 execution", {})
   ```
   If the target artifact on disk has been altered in any byte after approval was granted, execution fails closed with zero side effects.

3. **Single-Use Grant Consumption:**
   When `evaluate_request()` validates an `ApprovalGrant`, it atomically records the grant ID in `SQLiteAtomicGrantConsumptionStore` using a `BEGIN IMMEDIATE` transaction and primary key uniqueness constraint. Any second attempt to use the same grant fails immediately with `DENIED_HIL_GRANT_REPLAY`.

### EP-07 & EP-08: GUI Server Write Endpoints

1. Unconditional check in `GUIWorkbenchHandler.do_POST`:
   ```python
   user = self._get_auth_user()
   if not user or not user.is_cryptographically_verified():
       self._json_response({"status": "error", "error": "Authentication required for ..."}, status=401)
       return
   if not user.can_modify():
       self._json_response({"status": "error", "error": "Insufficient RBAC role for ..."}, status=403)
       return
   ```
2. An unauthenticated attacker receiving HTTP 401 produces **zero filesystem changes** and **zero state modifications**.
