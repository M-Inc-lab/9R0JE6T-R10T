//! R3V3R53//F0RG3 — Wave 6 (Phases 151–153): Direct Rust Port of `frida-gum`
//! (`gumstalker.c` & `gumx86relocator.c`) Basic-Block Code-Cache & RIP-Relative Relocator
//! (`open_source_frida_stalker_gum.rs`)
//!
//! Directly translates core Dynamic Binary Instrumentation (DBI) code-cache and relocation
//! algorithms from `frida-gum`:
//!   - `GumX86Relocator`: Detects RIP-relative instructions (`48 8B 05 disp32`, `48 8D 05 disp32`,
//!     `E8 rel32`, `E9 rel32`) when copying basic blocks from `orig_va` to `slab_va` and
//!     automatically adjusts signed 32-bit displacements or rewrites out-of-range branches
//!     into 14-byte absolute indirect jumps (`FF 25 00 00 00 00 <u64 target>`).
//!   - `GumStalkerBlock`: Synthesizes instrumented code-cache slabs with coverage counter
//!     probes (`LOCK INC QWORD PTR [counter_va]`) and inline hook trampolines.

#[derive(Debug, Clone)]
pub struct RelocatedInsn {
    pub orig_va: u64,
    pub slab_va: u64,
    pub orig_bytes: Vec<u8>,
    pub relocated_bytes: Vec<u8>,
    pub was_rip_relative: bool,
}

#[derive(Debug, Clone)]
pub struct StalkerInstrumentedBlock {
    pub orig_entry_va: u64,
    pub slab_entry_va: u64,
    pub relocated_insns: Vec<RelocatedInsn>,
    pub slab_bytes: Vec<u8>,
    pub coverage_counter_va: u64,
}

#[derive(Debug, Clone)]
pub struct StalkerInlineTrampoline {
    pub target_va: u64,
    pub hook_va: u64,
    pub trampoline_va: u64,
    pub overwrite_patch: Vec<u8>,
    pub trampoline_bytes: Vec<u8>,
}

/// Emit a 14-byte x86_64 absolute indirect jump (`jmp qword ptr [rip + 0]; dq target_va`)
pub fn emit_x64_abs_jmp(target_va: u64) -> Vec<u8> {
    let mut out = vec![0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    out.extend_from_slice(&target_va.to_le_bytes());
    out
}

/// Relocate a single x86_64 instruction from `orig_va` to `slab_va` (`gumx86relocator.c`)
pub fn relocate_x86_64_insn(insn_bytes: &[u8], orig_va: u64, slab_va: u64) -> RelocatedInsn {
    // 1. Relative CALL (0xE8 rel32) or JMP (0xE9 rel32)
    if insn_bytes.len() == 5 && (insn_bytes[0] == 0xE8 || insn_bytes[0] == 0xE9) {
        let orig_disp = i32::from_le_bytes([insn_bytes[1], insn_bytes[2], insn_bytes[3], insn_bytes[4]]) as i64;
        let target_va = (orig_va as i64).wrapping_add(5).wrapping_add(orig_disp) as u64;
        let new_disp = (target_va as i64).wrapping_sub((slab_va as i64).wrapping_add(5));
        if new_disp >= (i32::MIN as i64) && new_disp <= (i32::MAX as i64) {
            let mut rel = vec![insn_bytes[0]];
            rel.extend_from_slice(&(new_disp as i32).to_le_bytes());
            return RelocatedInsn {
                orig_va,
                slab_va,
                orig_bytes: insn_bytes.to_vec(),
                relocated_bytes: rel,
                was_rip_relative: true,
            };
        } else {
            return RelocatedInsn {
                orig_va,
                slab_va,
                orig_bytes: insn_bytes.to_vec(),
                relocated_bytes: emit_x64_abs_jmp(target_va),
                was_rip_relative: true,
            };
        }
    }

    // 2. 7-byte REX.W RIP-relative LEA/MOV (`48 8D 05 disp32` or `48 8B 05 disp32`)
    if insn_bytes.len() == 7 && insn_bytes[0] == 0x48 && (insn_bytes[1] == 0x8D || insn_bytes[1] == 0x8B) && (insn_bytes[2] & 0xC7) == 0x05 {
        let orig_disp = i32::from_le_bytes([insn_bytes[3], insn_bytes[4], insn_bytes[5], insn_bytes[6]]) as i64;
        let target_va = (orig_va as i64).wrapping_add(7).wrapping_add(orig_disp) as u64;
        let new_disp = (target_va as i64).wrapping_sub((slab_va as i64).wrapping_add(7));
        if new_disp >= (i32::MIN as i64) && new_disp <= (i32::MAX as i64) {
            let mut rel = vec![insn_bytes[0], insn_bytes[1], insn_bytes[2]];
            rel.extend_from_slice(&(new_disp as i32).to_le_bytes());
            return RelocatedInsn {
                orig_va,
                slab_va,
                orig_bytes: insn_bytes.to_vec(),
                relocated_bytes: rel,
                was_rip_relative: true,
            };
        }
    }

    RelocatedInsn {
        orig_va,
        slab_va,
        orig_bytes: insn_bytes.to_vec(),
        relocated_bytes: insn_bytes.to_vec(),
        was_rip_relative: false,
    }
}

/// Compile a Frida Stalker instrumented basic-block slab with coverage probe + relocated instructions
pub fn compile_stalker_basic_block(
    block_bytes: &[u8],
    orig_entry_va: u64,
    slab_entry_va: u64,
    coverage_counter_va: u64,
) -> StalkerInstrumentedBlock {
    let mut slab_bytes = Vec::new();
    // Coverage callout prologue: `push rax; mov rax, counter_va; inc qword ptr [rax]; pop rax`
    slab_bytes.push(0x50); // push rax
    slab_bytes.extend_from_slice(&[0x48, 0xB8]); // movabs rax, imm64
    slab_bytes.extend_from_slice(&coverage_counter_va.to_le_bytes());
    slab_bytes.extend_from_slice(&[0x48, 0xFF, 0x00]); // inc qword ptr [rax]
    slab_bytes.push(0x58); // pop rax

    let mut relocated_insns = Vec::new();
    let mut off = 0usize;
    while off < block_bytes.len() {
        let rem = block_bytes.len() - off;
        let cur_orig_va = orig_entry_va + (off as u64);
        let cur_slab_va = slab_entry_va + (slab_bytes.len() as u64);
        let insn_len = if rem >= 7 && block_bytes[off] == 0x48 && (block_bytes[off + 1] == 0x8D || block_bytes[off + 1] == 0x8B) && (block_bytes[off + 2] & 0xC7) == 0x05 {
            7
        } else if rem >= 5 && (block_bytes[off] == 0xE8 || block_bytes[off] == 0xE9) {
            5
        } else if rem >= 3 && block_bytes[off] == 0x48 && block_bytes[off + 1] == 0x89 {
            3
        } else {
            1
        };

        let rel = relocate_x86_64_insn(&block_bytes[off..off + insn_len], cur_orig_va, cur_slab_va);
        slab_bytes.extend_from_slice(&rel.relocated_bytes);
        relocated_insns.push(rel);
        off += insn_len;
    }

    StalkerInstrumentedBlock {
        orig_entry_va,
        slab_entry_va,
        relocated_insns,
        slab_bytes,
        coverage_counter_va,
    }
}

/// Build a Frida-Gum inline hook trampoline (`guminterceptor.c`)
pub fn build_gum_inline_trampoline(
    prologue_bytes: &[u8],
    target_va: u64,
    hook_va: u64,
    trampoline_va: u64,
) -> StalkerInlineTrampoline {
    let overwrite_patch = emit_x64_abs_jmp(hook_va);
    let mut trampoline_bytes = Vec::new();
    let rel = relocate_x86_64_insn(prologue_bytes, target_va, trampoline_va);
    trampoline_bytes.extend_from_slice(&rel.relocated_bytes);
    let resume_va = target_va + (prologue_bytes.len() as u64);
    trampoline_bytes.extend_from_slice(&emit_x64_abs_jmp(resume_va));

    StalkerInlineTrampoline {
        target_va,
        hook_va,
        trampoline_va,
        overwrite_patch,
        trampoline_bytes,
    }
}
