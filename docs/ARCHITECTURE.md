# 9R0JE6T-R10T Forensic Reverse-Engineering Platform — Architecture
**Document Version:** 1.0.0-verified  
**Author:** Principal Software Architect & Systems Programmer  
**Date:** 2026-10-27  

---

## 1. Architectural Principles

1. **Evidence-Driven Provenance:** Every finding (vulnerability, type inference, CFG edge, decompiler variable) must be explicitly linked to its cryptographic source hash, file offset, and tool chain evidence.
2. **Fail-Closed Security Boundaries:** Security-critical decisions (scope ledger authorization, sandbox execution, network access, token verification) default to deny.
3. **Multi-Tier Acceleration:** Zero-copy safe Rust native core handles high-throughput triage, FLIRT hashing, and micro-visor emulation; Python coordinates high-level AST synthesis, multi-engine orchestration, and REST/WebSocket APIs.
4. **Tool Agnosticism via Canonical Adapters:** Third-party RE tools (Ghidra, IDA, Rizin, angr) operate behind strictly typed adapters with standardized schemas and explicit capability reporting.

---

## 2. Logical Architecture & Subsystem Topology

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             API & PRESENTATION LAYER                             │
│   reverse_forge/gui_server.py (REST/SSE/WebSocket) │ reverse_forge/cli.py (CLI) │
└──────────────────────────┬───────────────────────────────────────┬───────────────┘
                           │                                       │
┌──────────────────────────▼───────────────────────────────────────▼───────────────┐
│                          SECURITY & GOVERNANCE LAYER                             │
│   reverse_forge/provenance.py (ScopeLedger, Canonical Path, ActionPermissions)  │
│   reverse_forge/firebase_sync.py (FirebaseAuthProvider, RBAC, Claims Verifier)   │
└──────────────────────────┬───────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────────────────────────┐
│                        ORCHESTRATION & INTENT ENGINE                             │
│   reverse_forge/intent_engine.py (Specification Compiler, 8 Objectives)          │
│   reverse_forge/investigation_workflow.py (9-Stage Adaptive Investigation)       │
│   reverse_forge/capability_registry.py (Catalog of 16 RE Categories)             │
│   rust_core/src/workflow_intent_engine.rs (Zero-Copy Native Rust Intent FFI)     │
└──────────────┬───────────────────────────┬───────────────────────────────┬───────┘
               │                           │                               │
┌──────────────▼──────────┐ ┌──────────────▼──────────┐ ┌──────────────────▼──────┐
│  FORMAT LOADERS & RECON │ │  STATIC ANALYSIS & IR   │ │ DYNAMIC & CONCOLIC EXEC │
│   reverse_forge/        │ │   reverse_forge/        │ │   reverse_forge/        │
│   ida_universal_formats │ │   function_indexer.py   │ │   micro_visor.py        │
│   pe_analyzer.py        │ │   unified_decompiler.py │ │   concolic_sym_exec.py  │
│   elf_macho_analyzer.py │ │   fine_grain_taint      │ │   dynamic_sandbox.py    │
│   rust_core/src/        │ │   rust_core/src/        │ │   rust_core/src/        │
│   parsers.rs            │ │   pcode_ssa.rs          │ │   visor.rs              │
└──────────────┬──────────┘ └──────────────┬──────────┘ └──────────────────┬──────┘
               │                           │                               │
┌──────────────▼───────────────────────────▼───────────────────────────────▼───────┐
│                         NATIVE EXECUTION BOUNDARY                                │
│   reverse_forge/native_rust_bridge.py (ctypes loader, fallback detection)        │
│   rust_core/bin/libreverse_forge_core.so (Compiled safe Rust cdylib)            │
│   rust_core/bin/reverse-forge-native (Standalone native CLI executable)          │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Subsystem Contracts & Data Models

### 3.1 Binary Format Parsing & Function Indexing
- **Contract:** Ingests untrusted `bytes` or file paths. Extracts headers, sections, virtual memory layouts, and discovers function entry points.
- **Key Types:**
  - `ZeroCopyBinarySummary`: Architecture, image base, entry point VA, section descriptors, Shannon entropy.
  - `WholeBinaryFunctionIndexer`: Scans binary for functions, builds basic block graphs, recovers call targets, and lifts disassembly to decompiler bundles.
  - `FunctionAnalysisBundle`: Name, virtual address, basic blocks, control flow graph edges, cross-references, decompiled C pseudocode.

### 3.2 Intermediate Representation (IR) & Decompilation
- **Contract:** Translates machine instructions into a formal intermediate representation, constructs Cytron SSA form, performs type and constant propagation, and emits structured C pseudocode.
- **Stages:**
  1. **Instruction Lifting:** Maps opcode bytes to Ghidra-compatible P-Code operations (`COPY`, `LOAD`, `STORE`, `INT_ADD`, `INT_SUB`, `BRANCH`, `CBRANCH`, `CALL`, `RETURN`).
  2. **SSA Form & Heritage:** Eliminates dead registers, inserts $\phi$-nodes at confluence basic blocks, renames varnodes to unique SSA versions (`rax_1`, `rax_2`).
  3. **Simplification Rules:** Constant propagation, dead-code elimination, algebraic simplification.
  4. **Control Flow Structuring:** Recovers `if-else` branches, `while/for` loops, and switch-case tables.

### 3.3 Dynamic Analysis & Micro-Visor
- **Contract:** Executes instructions in an under-constrained environment with automated fault recovery and bounded step budgets.
- **Key Components:**
  - `RustMicroVisor`: Emulates x86-64 instructions over arbitrary code slices. When a load/store faults on unmapped memory, the visor automatically allocates virtual pages and continues execution.
  - `ExecutionLimit`: 128 instructions maximum per trace to guarantee deterministic bounded execution.

### 3.4 Security & Scope Enforcement
- **Contract:** Every file access, static analysis job, and dynamic execution must be authorized against canonical path rules and action policies.
- **Action Matrix:**
  - `READ_HASH`: Compute SHA-256/MD5 and verify integrity.
  - `STATIC_ANALYSIS`: Parse headers, disassemble, decompile.
  - `DYNAMIC_SANDBOX`: Launch micro-visor or sandboxed execution (requires HIL gate approval).
  - `NETWORK_ACCESS`: Network egress during dynamic execution (denied by default).
  - `MODIFY_ARTIFACT`: Write patches or export reports.

---

## 4. Native Rust / C Execution Boundary

The native acceleration layer maintains a strictly audited FFI boundary:
1. **C-ABI Function Signatures:**
   ```c
   double rf_rust_entropy(const uint8_t *ptr, size_t len);
   uint16_t rf_rust_flirt_crc16(const uint8_t *ptr, size_t len);
   uint64_t rf_rust_fnv1a_64(const uint8_t *ptr, size_t len);
   uint64_t rf_rust_visor_exec(const uint8_t *code_ptr, size_t code_len, uint64_t base_va, size_t max_steps, size_t *out_steps, size_t *out_faults);
   size_t rf_rust_pcode_decompile(const uint8_t *code_ptr, size_t code_len, uint64_t base_va, uint8_t *out_buf, size_t out_buf_cap);
   ```
2. **Safe Rust Guarantees:** All 56 Rust modules inside `rust_core/src/` use safe Rust exclusively. Unsafe code is strictly limited to the `extern "C"` FFI wrapper layer in `src/lib.rs` for raw pointer dereferencing and bounds validation.
3. **Dual Execution Fallback:** If `cargo` or `libreverse_forge_core.so` is missing, `native_rust_bridge.py` automatically compiles `c_fallback_bridge.c` using the host C compiler (`gcc`/`clang`), maintaining 100% API compatibility.
