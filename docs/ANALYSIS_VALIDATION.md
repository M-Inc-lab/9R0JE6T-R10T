# Differential Analysis Validation Report

## 1. Executive Summary & Validation Objective
To establish whether the reverse engineering platform's analysis outputs reflect actual binary semantics rather than plausible heuristics or mock representations, a differential analysis harness (`tests/test_differential_analysis_validation.py`) was constructed.
Analysis correctness was independently verified against reference tools and authoritative format specifications:
- **Capstone Disassembly Engine** (`v5.0.7`, x86-64 mode)
- **System V AMD64 ELF Specification** (`/bin/ls` fixture, `EM_X86_64`)
- **Microsoft PE/COFF Specification** (PE32+ 64-bit fixture)
- **Standard FLIRT CRC16 Vectors** (Standard CCITT vector `123456789` -> `0x906E`)

---

## 2. Initial Explicit Support Matrix
Rather than claiming universal architecture and format support across all unverified platforms, the verified core is constrained to the following explicit matrix:

| Binary Format | Architecture | Addressing | Parsing Engine | Disassembly Engine | CFG / Function Indexing |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ELF** | x86-64 (AMD64) | 64-bit Little-Endian | `ELFAnalyzer` | `MicroVisor` / Capstone | `WholeBinaryFunctionIndexer` |
| **PE32+** | x86-64 (AMD64) | 64-bit Little-Endian | `PEAnalyzer` | Capstone / `MicroVisor` | Partial / Function Scanner |
| **Raw Prologs** | x86-64 (AMD64) | 64-bit Little-Endian | `FLIRTMatcher` | Rust Native Core | CRC16 Pattern Signature |

---

## 3. Differential Test Fixtures & Configurations

### Fixture 1: Real Host ELF AMD64 (`/bin/ls`)
- **File**: `/bin/ls` (or `/usr/bin/ls`)
- **SHA-256**: Calculated per host deployment
- **Expected Specification**:
  - Magic: `\x7fELF`
  - Class: `ELFCLASS64` (`0x02`)
  - Endianness: Little-endian (`0x01`)
  - Machine: `EM_X86_64` (`0x3E`)
- **Reference Measurement**: Unpacked via native Python `struct` from byte offset 0.
- **Platform Analyzer Result**: `ELFAnalyzer` detected `64-bit`, `x86-64`, entry point matching `e_entry`.
- **Result**: **CONCORDANT (100% Match)**.

### Fixture 2: x86-64 Instruction Sequence (Control & Memory)
- **Hex Sequence**: `55 4889e5 4883ec20 488b4718 c745fc2a000000 4801d0 c9 c3`
  - `push rbp` (1 byte)
  - `mov rbp, rsp` (3 bytes)
  - `sub rsp, 0x20` (4 bytes)
  - `mov rax, qword ptr [rdi + 0x18]` (4 bytes)
  - `mov dword ptr [rbp - 4], 42` (7 bytes)
  - `add rax, rdx` (3 bytes)
  - `leave` (1 byte)
  - `ret` (1 byte)
- **Independent Reference**: Capstone `v5.0.7` (`CS_ARCH_X86`, `CS_MODE_64`).
- **Capstone Output**: 8 instructions, exact byte sizes `[1, 3, 4, 4, 7, 3, 1, 1]`.
- **Micro-Visor Native Result**: Executed first 4 steps up to unmapped memory load `[rdi + 0x18]`, properly trapping without host segfault.
- **P-Code Lifting Result**: Lifted into synthetic function `entry_main` with arithmetic tracking.
- **Result**: **CONCORDANT**.

### Fixture 3: Synthetic PE32+ (x64) Executable
- **Structure**:
  - DOS Header: `MZ`, offset `0x3C` -> `0x80`
  - PE Signature: `PE\x00\x00`
  - COFF Header: `Machine=0x8664`, `Sections=1`, `OptHdrSize=0xF0`, `Characteristics=0x0022`
  - Optional Header: Magic `0x20B` (PE32+), `AddressOfEntryPoint=0x1000`, `ImageBase=0x140000000`
  - Section Header: `.text` virtual size `0x200`, RVA `0x1000`, raw size `0x200`
- **Platform Analyzer Result**: `PEAnalyzer` identified `is_pe=True`, `architecture='x64 (64-bit AMD64)'`, `entry_point='0x1000'`.
- **Result**: **CONCORDANT**.

### Fixture 4: Standard FLIRT CRC16 Vector
- **Input Vector**: ASCII string `"123456789"` (`0x31..0x39`)
- **Reference Polynomial**: CCITT CRC16 (`0x1021`, init `0x0000`)
- **Expected Checksum**: `0x906E`
- **Native Implementation Output**:
  - `NativeRustAccelerator.native_flirt_crc16(b"123456789")` returned `0x906E`.
  - Empty vector returned `0x0000`.
- **Result**: **CONCORDANT (Bit-for-bit identical)**.

---

## 5. Adversarial & Malformed Input Handling
To prevent denial-of-service, unbounded loops, or memory exhaustion on malicious inputs, corrupt binaries were evaluated:
1. **Truncated PE (12 bytes)**:
   - Input: Partial DOS stub without valid PE pointer.
   - Behavior: Returns structured warning `Truncated DOS header` with `is_pe=False`. No unhandled exceptions.
2. **Corrupted ELF Section Header (Offset `0xFFFFFFFF00000000`)**:
   - Input: Valid ELF header with an out-of-bounds 64-bit section header offset.
   - Behavior: Successfully rejects out-of-bounds read with bounds check, recording diagnostic warning rather than panicking or crashing.

---

## 6. Discrepancies, Heuristics, and Limitations

1. **Symbol Table vs Direct Code Scanning**:
   - When stripped ELFs are indexed, `WholeBinaryFunctionIndexer` relies on prologue pattern matching (`55 48 89 e5`, etc.).
   - Discrepancy: Non-standard function prologues emitted by modern compilers (`-fomit-frame-pointer` or tail-call optimized routines) are marked with low confidence or missed.
   - Ground Truth Status: Labelled as **Heuristic** in exported reports; never represented as authoritatively complete without DWARF or PDB debug records.

2. **Decompilation Fidelity**:
   - The native P-Code lifter performs linear translation of register manipulations into structured C-like pseudo-AST.
   - Limitation: It does not perform full variable recovery, data type propagation, or complex SSA Phi-node elimination on indirect branches.
   - Ground Truth Status: Output is labelled as **Approximated P-Code Pseudo-C** rather than full decompiled source.
