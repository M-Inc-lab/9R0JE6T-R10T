# 9R0JE6T-R10T Forensic Reverse-Engineering Platform — Test Strategy
**Document Version:** 1.0.0-verified  
**Author:** Principal Test Automation Architect & Quality Engineer  
**Date:** 2026-10-27  

---

## 1. Multi-Layer Verification Hierarchy

The test strategy for `9R0JE6T-R10T` spans six discrete verification layers to guarantee that claims of capability, correctness, and security are backed by empirical execution:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 6: Continuous Integration & Release Gates             │
├─────────────────────────────────────────────────────────────┤
│ Layer 5: End-to-End Forensic Investigation Workflows        │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Differential Validation vs Reference Engines       │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Adversarial, Malformed Binary & Fuzz Testing       │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Subsystem Integration & Service Boundaries         │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Unit Verification (Rust Native & Python Core)      │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Test Layer Specifications

### Layer 1: Unit Tests
- **Scope:** Header parsing, instruction length decoding, P-Code translation, SSA Cytron dominance frontiers, constant propagation, cryptographic token validation, and scope authorization.
- **Tools:** `pytest` (Python), `cargo test` (Rust).
- **Current Status:** 292 Python tests passing; 3 Rust crate tests passing.
- **Fail-Safe Requirement:** Any assertion failure halts CI; zero tolerance for test masking with `|| true` or empty exception handlers.

### Layer 2: Subsystem Integration Tests
- **Scope:** Cross-module data handoffs:
  - `WholeBinaryFunctionIndexer` → `UnifiedDecompilerPipeline` → C code generation.
  - `WorkflowIntentEngine` → `InvestigationWorkflow` → Stage Dispatcher.
  - `ScopeLedger` → `ProvenanceManager` → Read-only working copy isolation.
  - `GUIWorkbenchHandler` → REST API endpoints (`/api/functions`, `/api/decompile`, `/api/investigate/*`).

### Layer 3: Adversarial & Fuzz Tests
- **Scope:** Hostile, malformed, and boundary inputs designed to induce crashes or bypass security controls:
  - **Malformed Headers:** PE/ELF binaries with zeroed section counts, out-of-bounds offsets, truncated DOS headers.
  - **Path Traversal Attacks:** Targets containing `../`, null bytes, symlink loops, or absolute system paths (`/etc/shadow`).
  - **Adversarial Tokens:** Expired JWTs, unsigned tokens, tokens with tampered claim payloads, missing `Bearer` prefixes.
  - **Micro-Visor Loops:** Infinite `jmp $` instruction loops, self-modifying code, illegal opcodes, unmapped page faults.

### Layer 4: Differential Validation Tests
- **Scope:** Comparing native Rust and internal algorithms against established reference engines:
  - **FLIRT CRC-16:** Validated against known test vectors (`"123456789"` → `0x906E`).
  - **Shannon Entropy:** Native Rust SIMD implementation verified bit-for-bit against Python `math.log2` domain.
  - **Instruction Decoding:** Decoded byte lengths validated against Capstone / Zydis.
  - **C Pseudocode Structuring:** Control flow graph recovery validated against Cytron SSA ground truth.

### Layer 5: End-to-End (E2E) Forensic Workflows
- **Scope:** Validates the complete pipeline on benign ground-truth binary fixtures:
  - **Benign ELF Fixture:** `/bin/ls` (x86-64 SysV ELF) — Ingest → Index 183 functions → Extract `main` → Decompile → Emulate entry point → Export JSON evidence report.
  - **Benign PE Fixture:** Valid compiled PE32+ executable — Verify DOS/NT headers, export directory, relocations, import table, and decompiler recovery.

### Layer 6: CI Gates & Build Verification
- **Checks Executed on Every Push:**
  1. `cargo check --manifest-path rust_core/Cargo.toml` (clean compilation).
  2. `cargo test --manifest-path rust_core/Cargo.toml` (Rust test suite).
  3. `gcc -O3 -shared -fPIC -o rust_core/bin/libreverse_forge_core.so rust_core/c_fallback_bridge.c -lm` (Independent C-fallback verification).
  4. `gcc -O3 -o rust_core/bin/reverse-forge-native rust_core/standalone_cli.c rust_core/c_fallback_bridge.c -lm` (Native CLI build).
  5. `PYTHONPATH=. pytest` (Full 292-test Python regression suite).

---

## 3. Regression Testing Protocol

For every defect discovered:
1. **Reproduce:** Author a dedicated test fixture that explicitly fails against the unpatched codebase.
2. **Patch:** Apply the minimal, reviewable code fix adhering to fail-closed principles.
3. **Verify:** Confirm the reproducing test passes and all 292 regression tests remain green.
4. **Document:** Record the defect ID, root cause, and regression test path in `docs/OVERHAUL_BASELINE.md`.
