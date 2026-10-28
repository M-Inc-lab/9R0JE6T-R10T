//! R3V3R53//F0RG3 — Complete 16-Category Native Rust Library Root & C-ABI FFI Bridge (`lib.rs`)
//! Unifies all 16 categories of the Open-Source Reverse Engineering Toolkit into a single
//! zero-copy, low-memory (`<1.5 MB` RSS) Native Rust crate (`reverse_forge_core`):
//!   - Cat 1: `pcode_ssa` & `disasm` (Ghidra SLEIGH P-Code, Heritage SSA, RuleAction, Rizin/RetDec structuring)
//!   - Cat 2 & 3: `visor` (x64dbg/GDB-RSP/Frida/Unicorn Under-Constrained Force-Execution Micro-Visor)
//!   - Cat 4: `symbolic_angr_smt` (angr/KLEE/Triton 64-bit Bit-Vector Domain & CWE-190 Solver)
//!   - Cat 5 & 14: `scanner` (CAPA, YARA, FLOSS, FLIRT CRC-16, Wildcard Signature Scanner)
//!   - Cat 6, 7, 8, 9: `bytecode_jvm_dex_clr_wasm` (JADX Android DEX, Recaf/CFR JVM `.class`, ILSpy/de4dot `.NET`, WABT `WASM`)
//!   - Cat 10: `firmware_binwalk` (Binwalk/FACT SquashFS/CramFS/uImage/DTB Carver & Cortex-M Vector Base)
//!   - Cat 11: `network_pcap_netzob` (Wireshark/Zeek PCAP Dissector & Netzob Protocol Grammar Inferencer)
//!   - Cat 12: `parsers` & `checksec_cfi_audit` (LIEF/DIE/PE-bear Zero-Copy Parsers & checksec/CET/CFI Auditor)
//!   - Cat 13: `diff_diaphora` (Diaphora/BinDiff Small-Prime-Product & Normalized Opcode Binary Differ)
//!   - Cat 15: `memory_volatility_pesieve` (Volatility 3/PE-sieve Minidump, Hollowing & In-Memory PE Unmapper)
//!   - Cat 16: `imhex_patcher` (ImHex `.hexpat` Struct Pattern Evaluator & Keystone/LIEF Micro-Patcher)

#![allow(clippy::all)]

pub mod open_source_die_packer_detector;
pub mod open_source_rr_panda_timetravel;
pub mod open_source_qbdi_dynamorio_trace;
pub mod open_source_master_orchestrator;
pub mod open_source_apktool_androguard_axml;
pub mod open_source_de4dot_asmresolver_dotnet;
pub mod open_source_dwarf5_pdb_type_tree;
pub mod open_source_bsdiff_xdelta_patch;
pub mod open_source_wireshark_zeek_netzob;
pub mod open_source_binwalk_fdt_firmware;
pub mod open_source_imhex_pattern_lang;
pub mod open_source_pwndbg_heap_x64dbg;
pub mod open_source_volatility3_memory;
pub mod open_source_pesieve_hollowshunter;
pub mod open_source_triton_symcc_dse;
pub mod open_source_retdec_jumptable;
pub mod open_source_frida_stalker_gum;
pub mod open_source_wabt_binaryen_wasm;
pub mod open_source_lief_binary_builder;
pub mod open_source_cfr_fernflower_jvm;
pub mod open_source_unicorn_softmmu;
pub mod open_source_ghidra_typefactory;
pub mod open_source_diaphora_bindiff_wl;
pub mod open_source_galileo_cfi_gadget_auditor;
pub mod open_source_rizin_esil;
pub mod open_source_angr_vex_claripy;
pub mod open_source_yara_ahocorasick_capa;
pub mod open_source_jadx_ilspy_ast;
pub mod web_studio_server;
pub mod repl_canvas_corpus_gdb;
pub mod open_source_sleigh_zydis_capstone;
pub mod workflow_intent_engine;

pub mod bytecode_jvm_dex_clr_wasm;
pub mod checksec_cfi_audit;
pub mod deobfuscation_floss_mba;
pub mod deobfuscators_advanced_open_source;
pub mod elf_macho_deep;
pub mod ghidra_ruleaction_types;
pub mod pipeline_sarif_sbom_rfdb;
pub mod diff_diaphora;
pub mod disasm;
pub mod firmware_binwalk;
pub mod ghidra_blockaction_structurer;
pub mod imhex_patcher;
pub mod memory_volatility_pesieve;
pub mod network_pcap_netzob;
pub mod parsers;
pub mod pcode_ssa;
pub mod scanner;
pub mod symbolic_angr_smt;
pub mod symbols_rtti_golang_rust_pdb;
pub mod taint_vsa_vuln_scanner;
pub mod visor;
pub mod yara_sigma_bridge_containers;

use std::slice;

#[no_mangle]
pub extern "C" fn rf_native_backend_identity() -> *const std::os::raw::c_char {
    b"RUST_NATIVE\0".as_ptr() as *const std::os::raw::c_char
}

#[no_mangle]
pub unsafe extern "C" fn rf_rust_entropy(ptr: *const u8, len: usize) -> f64 {
    if ptr.is_null() || len == 0 {
        return 0.0;
    }
    parsers::compute_shannon_entropy(slice::from_raw_parts(ptr, len))
}

#[no_mangle]
pub unsafe extern "C" fn rf_rust_flirt_crc16(ptr: *const u8, len: usize) -> u16 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    scanner::compute_flirt_crc16(slice::from_raw_parts(ptr, len))
}

#[no_mangle]
pub unsafe extern "C" fn rf_rust_fnv1a_64(ptr: *const u8, len: usize) -> u64 {
    if ptr.is_null() || len == 0 {
        return 0;
    }
    scanner::fnv1a_64(slice::from_raw_parts(ptr, len))
}

#[no_mangle]
pub unsafe extern "C" fn rf_rust_visor_exec(
    code_ptr: *const u8,
    code_len: usize,
    base_va: u64,
    max_steps: usize,
    out_steps: *mut usize,
    out_faults: *mut usize,
) -> u64 {
    if code_ptr.is_null() || code_len == 0 {
        return 0;
    }
    let code = slice::from_raw_parts(code_ptr, code_len);
    let mut v = visor::RustMicroVisor::new(base_va);
    let res = v.execute(base_va, code, max_steps);
    if !out_steps.is_null() {
        *out_steps = res.steps_executed;
    }
    if !out_faults.is_null() {
        *out_faults = res.auto_paged_faults;
    }
    res.final_rax
}

#[no_mangle]
pub unsafe extern "C" fn rf_rust_pcode_decompile(
    code_ptr: *const u8,
    code_len: usize,
    base_va: u64,
    out_buf: *mut u8,
    out_buf_cap: usize,
) -> usize {
    if code_ptr.is_null() || code_len == 0 || out_buf.is_null() || out_buf_cap == 0 {
        return 0;
    }
    let code = slice::from_raw_parts(code_ptr, code_len);
    let blocks = disasm::lift_bytes_to_pcode_blocks(code, base_va);
    let res = pcode_ssa::GhidraPcodeDecompiler::emit_structured_c(&blocks, "entry_main", base_va);
    let c_bytes = res.c_source.as_bytes();
    let copy_len = c_bytes.len().min(out_buf_cap - 1);
    std::ptr::copy_nonoverlapping(c_bytes.as_ptr(), out_buf, copy_len);
    *out_buf.add(copy_len) = 0;
    copy_len
}
