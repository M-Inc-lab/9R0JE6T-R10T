//! R3V3R53//F0RG3 — Wave 8 (Phases 178–180): Direct Rust Port of `pwndbg` / `GEF` `ptmalloc2`
//! Heap Chunk & Safe-Linking Auditor + `x64dbg` / `TitanEngine` `DR0–DR7` Hardware Watchpoint Engine
//! (`open_source_pwndbg_heap_x64dbg.rs`)
//!
//! Directly translates the heap forensics and hardware debug register algorithms from:
//!   - `pwndbg` (`pwndbg/aglib/heap/ptmalloc.py`) & `GEF`:
//!     - Parses glibc `ptmalloc2` `malloc_chunk` headers (`prev_size`, `size & !7`,
//!       `PREV_INUSE` `0x1`, `IS_MMAPPED` `0x2`, `NON_MAIN_ARENA` `0x4`, `fd`, `bk`).
//!     - Demangles glibc 2.32+ `Safe-Linking` pointers (`demangle_safe_link(chunk_addr, mangled_fd)`)
//!       and runs cycle detection on `tcache` / `fastbin` lists to flag double-free vulnerabilities.
//!   - `x64dbg` / `TitanEngine` (`TitanEngine.Debugger.Breakpoints.cpp`):
//!     - Encodes and decodes x86_64 `DR7` hardware breakpoint control register bitfields
//!       (`L0..L3` local enable, `R/W0..3` trigger condition, `LEN0..3` watchpoint byte width).

use std::collections::{BTreeMap, BTreeSet};

pub const PREV_INUSE: u64 = 0x1;
pub const IS_MMAPPED: u64 = 0x2;
pub const NON_MAIN_ARENA: u64 = 0x4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtmallocChunk {
    pub addr: u64,
    pub prev_size: u64,
    pub size: u64,
    pub prev_inuse: bool,
    pub is_mmapped: bool,
    pub non_main_arena: bool,
    pub fd: u64,
    pub bk: u64,
}

#[derive(Debug, Clone)]
pub struct HeapArenaAuditReport {
    pub chunks_parsed: usize,
    pub tcache_double_free_detected: bool,
    pub unaligned_fd_detected: bool,
    pub cycle_nodes: Vec<u64>,
}

/// Demangle a glibc 2.32+ Safe-Linking pointer (`(chunk_addr >> 12) ^ mangled_ptr`)
pub const fn demangle_safe_link(chunk_addr: u64, mangled_ptr: u64) -> u64 {
    (chunk_addr >> 12) ^ mangled_ptr
}

/// Parse a raw 32-byte glibc `malloc_chunk` at `chunk_addr`
pub fn parse_ptmalloc_chunk(chunk_addr: u64, raw: &[u8], safe_linking: bool) -> Option<PtmallocChunk> {
    if raw.len() < 32 {
        return None;
    }
    let prev_size = u64::from_le_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let raw_size = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let raw_fd = u64::from_le_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
    let bk = u64::from_le_bytes(raw[24..32].try_into().unwrap_or([0; 8]));
    let fd = if safe_linking && raw_fd != 0 {
        demangle_safe_link(chunk_addr, raw_fd)
    } else {
        raw_fd
    };

    Some(PtmallocChunk {
        addr: chunk_addr,
        prev_size,
        size: raw_size & !7,
        prev_inuse: (raw_size & PREV_INUSE) != 0,
        is_mmapped: (raw_size & IS_MMAPPED) != 0,
        non_main_arena: (raw_size & NON_MAIN_ARENA) != 0,
        fd,
        bk,
    })
}

/// Audit a `tcache` / `fastbin` singly-linked list of chunks for double-free cycles and 16-byte alignment violations
pub fn audit_tcache_fastbin_list(chunks: &BTreeMap<u64, PtmallocChunk>, head_addr: u64) -> HeapArenaAuditReport {
    let mut visited = BTreeSet::new();
    let mut cycle_nodes = Vec::new();
    let mut double_free = false;
    let mut unaligned = false;
    let mut cur = head_addr;

    while cur != 0 {
        if (cur & 0xF) != 0 {
            unaligned = true;
            break;
        }
        if !visited.insert(cur) {
            double_free = true;
            cycle_nodes.push(cur);
            break;
        }
        if let Some(ch) = chunks.get(&cur) {
            cur = ch.fd;
        } else {
            break;
        }
    }

    HeapArenaAuditReport {
        chunks_parsed: chunks.len(),
        tcache_double_free_detected: double_free,
        unaligned_fd_detected: unaligned,
        cycle_nodes,
    }
}

/// Encode an x86_64 `DR7` hardware breakpoint control register value (`TitanEngine` / `x64dbg` convention)
/// `slot`: 0..=3 (`DR0`..`DR3`), `rw_cond`: `0b00` (exec), `0b01` (write), `0b11` (read/write),
/// `byte_len`: 1, 2, 4, or 8 bytes.
pub const fn encode_x64_dr7_watchpoint(current_dr7: u64, slot: usize, rw_cond: u8, byte_len: usize) -> u64 {
    if slot > 3 {
        return current_dr7;
    }
    let len_bits: u64 = match byte_len {
        1 => 0b00,
        2 => 0b01,
        8 => 0b10,
        4 => 0b11,
        _ => 0b00,
    };
    let local_enable_bit = 1u64 << (slot * 2);
    let cond_shift = 16 + (slot * 4);
    let clear_mask = !((0xFu64 << cond_shift) | (0b11u64 << (slot * 2)));
    let field = ((len_bits & 0b11) << 2) | ((rw_cond as u64) & 0b11);
    (current_dr7 & clear_mask) | local_enable_bit | (field << cond_shift)
}
