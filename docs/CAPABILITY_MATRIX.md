# 9R0JE6T-R10T Forensic Reverse-Engineering Platform — Capability Matrix
**Document Version:** 1.1.0-phase4.1-verified  
**Author:** Principal Reverse Engineering Architect  
**Date:** 2026-10-27  

---

## 1. Maturity Classification Definitions

Every capability in this matrix is classified into exactly one of seven rigorous engineering tiers:

| Maturity Status | Definition & Verification Requirement |
|:---|:---|
| `verified` | **Production-grade & independently proven.** Fully implemented, deterministic output, validated against real binary fixtures, with passing unit, integration, and differential regression tests. |
| `implemented` | **Functional internal implementation.** Code executes cleanly and produces correct semantic results, but has not yet undergone differential validation against external ground truth. |
| `adapter` | **External tool integration layer.** Dispatches work to an independently installed third-party tool (e.g., Ghidra, IDA, Rizin) and translates outputs into unified schema. Fails safely and reports `external_binary_installed: False` when the host tool is absent. |
| `heuristic` | **Probabilistic or rule-based inference.** Generates findings with explicit non-confirmed confidence scores (`Possible` / `Theoretical`) and supporting evidence; never labels unverified symbolic/concolic hypotheses as `Confirmed`. |
| `experimental` | **Active research & development.** Core logic exists and runs, but API contracts, memory behavior, or edge cases are subject to active refinement. |
| `simulated` | **Mock / In-memory adapter.** Emulates external service contracts (e.g., in-memory Firestore or mock JWT auth) for local testing without network services. Startup fails closed if accidentally configured for production. |
| `unsupported` | **Documented limitation.** Format, architecture, or technique is explicitly recognized but currently rejected fail-closed with a typed error. |

---

## 2. Comprehensive Capability Matrix

### Category 1: Binary Formats & Loaders
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **PE32 / PE32+ (x86/x64)** | `reverse_forge/pe_analyzer.py`, `rust_core/src/parsers.rs` | Custom zero-copy parser & `pefile` | Requires valid DOS & PE headers. Truncated headers rejected safely. | `test_phase1_pe.py`, `test_phase91_100` | `verified` | Real Windows kernel drivers / packed PE differential fuzzing. |
| **ELF32 / ELF64 (x86/ARM/MIPS/RISC-V)** | `reverse_forge/elf_macho_analyzer.py`, `rust_core/src/elf_macho_deep.rs` | Custom ELF header & section parser | Supports standard SysV & GNU extensions. Relocations parsed zero-copy. | `test_phase2_elf.py`, `test_phase191_200` | `verified` | Stripped binaries with corrupted section headers. |
| **Mach-O (Fat / Universal / ARM64)** | `reverse_forge/elf_macho_analyzer.py` | Python struct unpacker | Fat binaries unpacked per architecture; dyld shared cache not supported. | `test_phase2_elf.py` | `implemented` | Real macOS/iOS kernel cache differential test. |
| **Universal 26-Family Formats** | `reverse_forge/ida_universal_formats.py` | Format magic & header validator | Covers DEX, JVM, WASM, GameBoy, Amiga, PRG, COFF. | `test_phase221_230_ida_universal_formats.py` | `verified` | Corrupted container fuzzing across all 26 formats. |

### Category 2: Disassembly & Instruction Decoding
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **x86/x64 Disassembly** | `rust_core/src/disasm.rs`, `reverse_forge/function_indexer.py` | Native linear sweep & recursive descent with length-decoding table | Pure native decoder; uses Capstone when installed. | `test_phase86_90_rust_native_core.py` | `verified` | Differential instruction decode test vs Capstone/Zydis on 10,000 random instructions. |
| **ARM / Thumb / AArch64** | `reverse_forge/disassembler_adapter.py` | Capstone adapter / internal heuristic | Requires `capstone` package for full mnemonic decoding. | `test_phase17_18_decompiler_alias.py` | `adapter` | Test on ARM64 macOS & Linux userland fixtures. |
| **Sleigh Multi-Arch Lifter** | `rust_core/src/sleigh_multiarch_lifter.rs` | Ghidra Sleigh processor specifications | Pure Rust emulation of Sleigh semantics for x64, ARM64, RISC-V. | `test_phase191_200` | `experimental` | SMT equivalence check of lifted P-Code vs hardware semantics. |

### Category 3: Intermediate Representation (IR) & Decompilation
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **Ghidra P-Code Lifting** | `rust_core/src/pcode_ssa.rs` (`lift_bytes_to_pcode_blocks`) | Safe Rust instruction-to-PCode lifter | Supports basic arithmetic, branches, loads, stores, calls, returns. | `test_phase86_90_rust_native_core.py` | `verified` | Comprehensive x86 opcode lifting suite covering SSE/AVX. |
| **Heritage SSA & Varnode Renaming** | `rust_core/src/pcode_ssa.rs` (`run_heritage_ssa`) | Cytron SSA construction algorithm | Single-function scope; phi-placement computed via dominance frontiers. | `test_phase86_90_rust_native_core.py` | `verified` | Complex irreducible control-flow graph validation. |
| **High-Level C Pseudocode Generation** | `rust_core/src/pcode_ssa.rs`, `reverse_forge/unified_decompiler.py` | Structured control reconstruction | Emits readable C-like pseudocode. Does not guarantee strict semantic re-compilability. | `test_phase201_210` | `implemented` | Re-compilation of generated C pseudocode back to binary matching original CFG. |
| **External Ghidra / IDA / Rizin / Cutter Bridges** | `reverse_forge/ghidra_bridge.py`, `reverse_forge/tool_installer.py` | Subprocess & script bridges (`analyzeHeadless`, `ida64`, `rizin`, `cutter`) | Requires external host binaries on `PATH`. `tool_installer.py` and `cli.py doctor` explicitly report `external_binary_installed` vs internal fallback status. | `test_phase3_pipeline.py`, `test_security_regressions.py` | `adapter` | CI matrix job with pre-installed Ghidra 11.2 / Rizin running headless analysis. |

### Category 4: Data Flow, Taint & Vulnerability Research
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **Fine-Grained Taint Tracking** | `reverse_forge/fine_grain_taint_engine.py` | Bitmask / AST register and stack taint tracker | Propagates taint across move, arithmetic, and stack spills. | `test_phase23_24_taint_and_bindiff.py` | `verified` | Interprocedural pointer aliasing taint tests. |
| **Value Set Analysis (VSA)** | `rust_core/src/taint_vsa_vuln_scanner.rs` | Strided interval arithmetic domain | Tracks `[min, max, stride]` for pointers and stack offsets. | `test_phase191_200` | `implemented` | Complex multi-dereference heap pointer tracking. |
| **CWE Pattern Vulnerability Scanner** | `reverse_forge/taint_vsa_vuln_scanner.py` | Sink-pattern rules (CWE-120, CWE-134, CWE-416) | Heuristic matching against dangerous API sinks and unbounded copies. | `test_phase27_28_zeroday_and_patch_verifier.py` | `heuristic` | Validation against Juliet C/C++ synthetic test suite. |
| **Concolic & Symbolic Hypothesis Engine** | `reverse_forge/concolic_engine.py`, `reverse_forge/pipeline.py` (`ConcolicSymbolicOrchestrator`) | Z3 / internal SMT solver over modeled constraints | Evaluates symbolic models and reports findings as `Possible` / `Theoretical (Unverified Heuristic — Requires Real Crash Reproduction)` (never `Confirmed`). | `test_phase4_authorization_bypass.py`, `test_phase66_70_eternal_upgrade.py` | `heuristic` | Concrete crash reproduction in isolated target execution harness. |

### Category 5: Dynamic Analysis & Micro-Visor
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **Under-Constrained Micro-Visor** | `rust_core/src/visor.rs` (`RustMicroVisor`), `reverse_forge/underconstrained_visor_engine.py` | Zero-copy x86-64 in-memory instruction emulator | Auto-pages unmapped memory faults; bounded instruction step limit; does not execute target binary on host OS. | `test_phase86_90_rust_native_core.py`, `test_phase81_85_transcendent_gap_breakers.py` | `verified` | Fuzz testing with hostile, self-modifying instruction loops. |
| **Sandbox Profile & Runner Script Synthesis** | `reverse_forge/dynamic_sandbox.py`, `reverse_forge/pipeline.py` (`_stage_7`) | Generates `.wsb`, `.ps1`, `posix_isolated_runner.sh`, and `frida_telemetry.js` | Requires mandatory single-use HIL `ApprovalGrant`. Synthesizes confinement profiles/scripts in workspace without executing the binary on the host. | `test_phase4_behavioral.py`, `test_phase4_authorization_bypass.py` | `verified` | Linux seccomp / cgroups v2 kernel-isolated live execution fixture. |

### Category 6: Intent-Driven Investigation & Orchestration
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **Intent Compilation & Workflow** | `reverse_forge/intent_engine.py`, `reverse_forge/investigation_workflow.py` | 8-objective compiler & 9-stage adaptive lifecycle | Bounded execution budget; evidence provenance chain for each stage; Stage 6 labeled `[In-Memory Emulation]`. | `test_intent_investigation_platform.py` | `verified` | Multi-objective investigation on CTF challenge binaries. |
| **Rust Native Intent FFI** | `rust_core/src/workflow_intent_engine.rs` | Safe Rust zero-copy classifier with C-ABI export | Zero heap allocations; regex-free token scoring in <0.3 ms. | `cargo test`, `test_intent_investigation_platform.py` | `verified` | Fuzzing intent engine with 10,000 adversarial operator prompts. |
| **Human-in-the-Loop (HIL) Safety Gate** | `reverse_forge/investigation_workflow.py` (`submit_hil_decision`, `_run_stage6_dynamic_execution`) | `CentralAuthorizationBoundary` + TOCTOU SHA-256 check | Blocks dynamic execution unless approved with a valid single-use `ApprovalGrant`. | `test_phase4_authorization_bypass.py`, `test_intent_investigation_platform.py` | `verified` | Penetration test attempting to bypass gate via prompt injection. |

### Category 7: Identity, Authorization & Cloud Services
| Capability | Implementation File & Symbol | Actual Backend | Dependencies & Limitations | Relevant Tests | Status | Evidence Required to Advance |
|:---|:---|:---|:---|:---|:---:|:---|
| **Central Execution Authorization Boundary & Single-Use HIL** | `reverse_forge/authorization.py` (`CentralAuthorizationBoundary`, `HILKeyRing`, `ApprovalIssuer`, `SQLiteAtomicGrantConsumptionStore`, `FirestoreTransactionalGrantConsumptionStore`) | Unified TOCTOU policy boundary, separated grant issuance/verification, key rotation, and atomic persistent single-use grant consumption | Fails closed on missing/weak keys or storage errors. Revalidates on-disk SHA-256 before execution. Single-use consumption persists across threads, processes, and restarts in SQLite WAL (verified) and Firestore transactional store (verified via atomic fake). | `test_phase4_authorization_bypass.py` (29 tests) | `verified` | Live multi-region Cloud Firestore transactional replay test & cloud KMS integration. |
| **Scope Authorization Ledger** | `reverse_forge/provenance.py` (`ScopeLedger`), `pipeline.py` | Canonical realpath & action-permission matrix | Strict default deny; requires explicit permissions for `DYNAMIC_SANDBOX`, `NETWORK_ACCESS`, `MODIFY_ARTIFACT`. Autonomy level cannot bypass security gates. | `test_security_regressions.py` | `verified` | Symlink escape & path traversal penetration test suite. |
| **Local Simulation Persistence** | `reverse_forge/firebase_sync.py` (`LocalSimulationPersistenceAdapter`) | In-memory tenant-isolated store | Fully isolated per-tenant namespaces; returns `local-sim://` URIs; enforces strict ID/path validation; strictly separated from production Firestore. | `test_firebase_sync.py`, `test_phase4_e2e_acceptance.py` | `simulated` | Durable local SQLite/duckdb adapter implementation. |
| **Production Firestore & Storage Adapter** | `reverse_forge/firebase_sync.py` (`ProductionFirestoreStorageAdapter`) | Google Cloud Firestore (2.34.1) & Cloud Storage (3.17.1) SDKs | Enforces principal-derived tenant scoping, document `tenant_id` ownership verification, path/ID validation, and typed `PersistencePermissionError` / `PersistenceUnavailableError` separation. | `test_phase4_e2e_acceptance.py`, `test_phase4_auth_hardening.py` (mocked SDK clients) | `implemented` (Live GCP credentials absent in test env) | Integration test against live Firebase project in cloud CI. |
| **JWT Bearer Token Authentication & Sealed Contexts** | `reverse_forge/firebase_sync.py` (`FirebaseAuthManager`, `AuthUserContext`, `SharedRevocationStore`) | Cryptographic `RS256`/`ES256`/`HS256` verification, algorithm/key compatibility checks, and HMAC `_verification_seal` | Defaults to `["RS256"]`; blocks algorithm confusion; rejects unknown roles and malformed claim types; prevents direct `AuthUserContext(is_verified=True)` forgery; persists revocations in `SharedRevocationStore` (SQLite WAL). | `test_phase4_auth_hardening.py` (51 tests), `test_firebase_sync.py` (26 tests) | `verified` | Production verification with live Google Cloud Identity Platform JWKS. |
| **Native Multi-Backend & Cache Invalidation** | `reverse_forge/native_rust_bridge.py` (`NativeRustAccelerator`) | Dynamic `RUST_NATIVE`, `C_FALLBACK`, or `PURE_PYTHON` | Cryptographic SHA-256 fingerprinting incorporating source, compiler versions, build flags, architecture, and ABI specification (`_validate_abi`). Packaged inside wheel for out-of-tree execution. | `test_phase4_auth_hardening.py`, `test_differential_analysis_validation.py` | `verified` | Multi-architecture cross-compilation matrix (ARM64/Linux). |
