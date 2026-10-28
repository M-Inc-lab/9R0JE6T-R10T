# R3V3R53//F0RG3 — Phase 4.2 Threat Model & Trust Boundary Hardening

**Repository:** `M-Inc-lab/9R0JE6T-R10T` (`R3V3R53//F0RG3`)  
**Document Version:** 4.2.0  
**Date:** 2026-10-28  

---

## 1. Trust Boundary Additions in Phase 4.2

In Phase 4.2, all remaining conditional gates based on runtime environment (`REVERSE_FORGE_ENV`), mode flags (`strict_auth=False`), and caller-supplied parameters were eliminated from execution paths:

### Boundary TB-2.1: Human-in-the-Loop Resumption Gate (`InvestigationWorkflowEngine.submit_hil_decision`)
- **Threat Vector:** An attacker or untrusted caller in a non-production environment calls `submit_hil_decision(inv_id, action="dynamic_execution", decision="APPROVE_SANDBOXED")` without providing an operator identity (`principal`) or cryptographic approval grant (`approval_grant`).
- **Phase 4.2 Enforcement:**
  - Unconditional enforcement of `CentralAuthorizationBoundary.evaluate_request()`.
  - Zero environment-based bypasses: `REVERSE_FORGE_ENV != "production"` and `strict_auth=False` are non-bypassing no-ops.
  - Fail-closed: missing or unverified credentials fail immediately with `AuthorizationDeniedError(DENIED_UNVERIFIED_IDENTITY)`.

### Boundary TB-2.2: State History Integrity (`InvestigationWorkflowEngine._is_hil_approved`)
- **Threat Vector:** An attacker injects or deserializes an approval record `{"action": "dynamic_execution", "decision": "APPROVE_SANDBOXED"}` into `InvestigationState.hil_history` to trick subsequent stage executions into running dynamic analysis.
- **Phase 4.2 Enforcement:**
  - `_is_hil_approved()` requires both `decision == "APPROVE_SANDBOXED"` **and** `cryptographic_auth is True`.
  - The `cryptographic_auth` boolean is set exclusively by `submit_hil_decision()` upon successful `CentralAuthorizationBoundary` grant consumption.

### Boundary TB-1.1: GUI Workbench Write Boundary (`/api/upload` & `/api/annotate`)
- **Threat Vector:** An unauthenticated network caller sends POST requests to `/api/upload` or `/api/annotate` without an `Authorization` header when running outside production.
- **Phase 4.2 Enforcement:**
  - Unconditional authentication check: requests lacking a valid, cryptographically verified `AuthUserContext` are terminated with HTTP 401.
  - Unconditional RBAC check: identities lacking `can_modify()` permission are terminated with HTTP 403.
  - Zero side effects: no files are written to disk and no annotations are stored in state on authorization failure.

---

## 2. Updated Threat Matrix (Phase 4.2 Additions)

| Threat ID | Adversary Goal | Attack Vector | Mitigation & Verification |
|---|---|---|---|
| **TM-01** to **TM-06** | See `docs/PHASE4_1_THREAT_MODEL.md` | Grant forgery, replay, unsealed identity, TOCTOU binary modification, direct stage bypass, tenant traversal | Bounded in Phase 4.1. |
| **TM-07** | Bypass HIL authorization in dev/test/staging environments | Invoke `submit_hil_decision()` with `decision="APPROVE_SANDBOXED"` while `REVERSE_FORGE_ENV != "production"` and `strict_auth=False`. | Conditional `enforce_boundary` check eliminated. Evaluation is unconditional; unverified credentials fail closed. Tested in `test_phase4_2_hil_bypass_closure.py`. |
| **TM-08** | History poisoning to trigger Stage 6 dynamic execution | Inject fake approval record into `InvestigationState.hil_history` without cryptographic verification. | `_is_hil_approved()` requires `cryptographic_auth: True`. Injected or legacy unauthenticated records are rejected. Tested in `test_phase4_2_hil_bypass_closure.py`. |
| **TM-09** | Unauthenticated binary upload or annotation injection | POST to `/api/upload` or `/api/annotate` without `Authorization` header in non-production mode. | Conditional auth check removed; both endpoints require verified identity and `can_modify()` role unconditionally. Tested in `test_phase4_2_hil_bypass_closure.py`. |
