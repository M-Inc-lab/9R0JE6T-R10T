# 9R0JE6T-R10T Forensic Reverse-Engineering Platform — Engineering Backlog
**Document Version:** 1.0.0-verified  
**Author:** Principal Software Architect & Verification Lead  
**Date:** 2026-10-27  

---

## 1. Prioritization Framework

Items are prioritized according to the non-negotiable engineering principles:
1. **P0 (Security & Correctness Foundations):** Fail-closed authorization, memory safety, boundary enforcement, reproducible builds.
2. **P1 (Core Analytical Depth):** Control-flow graph fidelity, calling-convention recovery, SSA intermediate representation, whole-binary function indexing.
3. **P2 (Orchestration & Investigation Intelligence):** Bounded hypothesis planning, HIL gates, provenance tracking, capability scoring.
4. **P3 (Integration & Persistence):** Durable database persistence, Firebase emulator support, tool adapters (Ghidra, IDA, Rizin).
5. **P4 (Competitive Evaluation & Verification):** Ground-truth benchmarks against IDA Pro / Ghidra on benign ELF/PE fixtures.

---

## 2. Prioritized Epics & User Stories

### Epic 1: Security Hardening & Fail-Closed Boundaries (P0) — *IN PROGRESS / MILESTONE 1*
- [x] **RF-SEC-01 (ScopeLedger Overhaul):** Replace `allow_all=True` defaults with fail-closed canonical real-path validation and `ActionPermission` segregation.
  - *Acceptance Criteria:* `ScopeLedger()` with no arguments rejects all paths. Path traversal (`../`, null bytes) rejected. Symlinks resolving outside allowed root are rejected. Actions (`READ_HASH`, `STATIC_ANALYSIS`, `DYNAMIC_SANDBOX`) gated independently. Passing in `tests/test_security_regressions.py`.
- [x] **RF-SEC-02 (Firebase Authentication Hardening):** Guard mock fallback behind `REVERSE_FORGE_ENV=development`.
  - *Acceptance Criteria:* In production mode, missing `Authorization` header returns `None` (401); unsigned JWTs are rejected; expired tokens (`exp < now`) are rejected.
- [ ] **RF-SEC-03 (Seccomp & Cgroups Container Sandbox):** Containerize dynamic analysis with Linux `seccomp-bpf` syscall filters and cgroups memory limits (256 MB max).
  - *Acceptance Criteria:* Dynamic binary cannot execute network syscalls or open paths outside ephemeral container mount.

### Epic 2: Build Integrity & Native Linkage (P0)
- [x] **RF-BLD-01 (Standalone Native Binary Linkage):** Ensure `reverse-forge-native` compiles cleanly from `standalone_cli.c` with `c_fallback_bridge.c` and exports all required subcommands.
  - *Acceptance Criteria:* Subcommands `doctor`, `die-scan`, `rr-timetravel`, `qbdi-drcov`, and `omni-audit` execute with exit status 0 and output valid JSON.
- [ ] **RF-BLD-02 (Deterministic Build Cache & ABI Fingerprinting):** Compute compiler and source hash fingerprints before native library load.
  - *Acceptance Criteria:* Stale or mismatched `.so` binaries are rejected with explicit rebuild prompt.

### Epic 3: Core RE Decompilation & Intermediate Representation (P1)
- [x] **RF-DEC-01 (Ghidra P-Code SSA Lifting):** Safe Rust implementation of Cytron SSA form with dominance frontiers and constant propagation.
  - *Acceptance Criteria:* P-Code decompiler outputs simplified C pseudocode in <3 ms.
- [ ] **RF-DEC-02 (Advanced Control Flow Structuring):** Implement Noam Chomsky / Tarjan dominator tree loop and `switch-case` structuring.
  - *Acceptance Criteria:* Irreducible CFGs decomposed into structured dispatchers without infinite loops.

### Epic 4: Investigation Intelligence & Bounded Planning (P2)
- [x] **RF-INT-01 (Zero-Copy Intent Classification):** Safe Rust FFI token classifier and Python specification compiler for 8 investigation objectives.
  - *Acceptance Criteria:* Compiles operator prompt to bounded DAG plan with time and step limits in <0.3 ms.
- [x] **RF-INT-02 (Human-in-the-Loop Safety Gate):** Enforcement callback for consequential actions (dynamic execution, patch application).
  - *Acceptance Criteria:* Autonomous bypass strictly blocked; prompts for operator signature and records audit entry.

### Epic 5: Empirical Benchmarking & Competitive Evaluation (P4)
- [x] **RF-BMK-01 (Empirical Baseline Specification):** Comprehensive evaluation framework across 6 dimensions with documented reference fixtures (`/bin/ls`, synthetic PE32+, Juliet test suite).
  - *Acceptance Criteria:* Published in `docs/BENCHMARK_METHODOLOGY.md` with measured microbenchmark table.
- [ ] **RF-BMK-02 (Automated Benchmark Harness):** CLI tool `python -m reverse_forge.cli benchmark` to output machine-readable JSON performance reports comparing cold vs warm cache states.
